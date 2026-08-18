//! SQLite 适配器：在单个 SQLite 文件上同时落实 `CatalogStore` 与 `SearchIndex`
//! 两个端口（见 ADR-0001：FTS5 单存主线）。
//!
//! 本 crate 是 hexagonal 架构里的 driven adapter——只依赖 domain + ports 的抽象，
//! 把端口契约翻译成具体的 SQLite/FTS5 SQL，绝不反向依赖 application。
//!
//! 唯一例外：CJK bigram transform（ADR-0007）与 RFC3339/ISO-8601 时间戳解析按约定
//! 放在 application crate（`cjk` 模块 / `parse_search_instant`），由本 crate 在 FTS
//! 写入/查询两侧与时间过滤谓词的标量函数中调用（索引与查询必须共享同一 transform、
//! 过滤谓词与请求边界必须共享同一解析才能一致），纯函数无 use-case 语义。

mod cas;
mod lease;
mod source_fs;

pub use cas::{cas_activate, read_current, write_current};
pub use lease::WriterLease;
pub use source_fs::{
    FileSource, SnapshotFs, capture, open_snapshot_source, read_verified, verify_snapshot,
};

use agent_session_grep_application::{bigram_cjk, parse_search_instant};
use agent_session_grep_domain::{
    EvidenceSpan, IdKind, Message, MessageEdge, MessagePlacement, MessageRelation, PlacementId,
    Role, SessionContextGraph, SourceDocument, StableId, ToolActivity,
};
use agent_session_grep_ports::{
    CatalogEntry, CatalogStore, ContextGraphStore, ContextStats, MessageContextCandidate,
    PortError, PortResult, ResumeClaimsStore, SearchFacets, SearchHit, SearchIndex, SearchQuery,
    SemanticIndex, SessionResumeMetadata, SidechainFacet, SourcePlacement, SourceResumeClaim,
};
use rusqlite::{Connection, OptionalExtension};
use std::any::Any;
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// Translate adapter failures into the stable port error vocabulary.
///
/// SQLite BUSY/LOCKED conditions are expected writer contention and therefore
/// retryable. The diagnostic is intentionally generic so backend paths or raw
/// SQLite messages cannot escape through the protocol boundary.
fn backend<E: std::fmt::Display + 'static>(e: E) -> PortError {
    let any = &e as &dyn Any;
    if any.downcast_ref::<rusqlite::Error>().is_some_and(|error| {
        matches!(
            error,
            rusqlite::Error::SqliteFailure(sqlite, _)
                if matches!(
                    sqlite.code,
                    rusqlite::ErrorCode::DatabaseBusy
                        | rusqlite::ErrorCode::DatabaseLocked
                )
        )
    }) {
        PortError::WriterBusy("SQLite storage is busy or locked by another writer".into())
    } else {
        PortError::Backend(e.to_string())
    }
}

static NEXT_OPERATION_ID: AtomicU64 = AtomicU64::new(0);

/// 批量 `IN (...)` 查询的单块 id 上限。SQLite 的变量上限是 999（旧版）/
/// 32766（3.32+），一个大 batch 的 placement/entity 数远超此限，必须分块。
const BATCH_IN_CHUNK: usize = 500;
/// Session 元数据搜索投影（`session_fts.text`）单字段的字符上限（schema v11）。
const SESSION_SEARCH_FIELD_CHARS: usize = 4096;

/// 批量 INSERT 每块行数。
///
/// 借鉴 hstry `bulk_insert_messages_in_tx`（MIT，
/// hstry/crates/hstry-core/src/db.rs:2990）：同一事务内用多行 VALUES 语句
/// 替代逐行 prepared execute，把往返次数从 N 压到 N/CHUNK。块内参数数
/// 不得超过 SQLite 默认的 SQLITE_MAX_VARIABLE_NUMBER（999）；本文件最宽的
/// 批量语句是 message_placements 的 8 列，8 × 100 = 800，与 hstry 的
/// `COLS * ROWS_PER_CHUNK <= 950` 编译期断言保持同一保守上限（db.rs:3058）。
const BULK_INSERT_ROWS_PER_CHUNK: usize = 100;
const _: () = assert!(8 * BULK_INSERT_ROWS_PER_CHUNK <= 950);

type PlacementInsertRow<'a> = (
    &'a str,
    &'a str,
    &'a str,
    &'a str,
    i64,
    i64,
    Option<i64>,
    Option<i64>,
);

/// 生成多行 VALUES 元组串：`rows` 个 `(?,?,...)`（每元组 `cols` 个占位符）。
fn multi_row_values(rows: usize, cols: usize) -> String {
    let mut sql = String::new();
    for row in 0..rows {
        if row > 0 {
            sql.push(',');
        }
        sql.push('(');
        for col in 0..cols {
            if col > 0 {
                sql.push(',');
            }
            sql.push('?');
        }
        sql.push(')');
    }
    sql
}

/// 生成 `IN (...)` 子句的占位符串：`count` 个逗号分隔的 `?`。
fn in_placeholders(count: usize) -> String {
    vec!["?"; count].join(",")
}

/// 把 id 列表切成不超过 [`BATCH_IN_CHUNK`] 的块（每块一个 `IN (...)` 查询）。
fn chunk_ids<T: AsRef<str>>(ids: &[T]) -> Vec<&[T]> {
    ids.chunks(BATCH_IN_CHUNK).collect()
}

fn unix_ms() -> PortResult<i64> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(backend)?
        .as_millis();
    i64::try_from(millis).map_err(backend)
}

fn operation_id() -> PortResult<String> {
    let seq = NEXT_OPERATION_ID.fetch_add(1, Ordering::Relaxed);
    Ok(format!(
        "op_v1_{}_{}_{}",
        unix_ms()?,
        std::process::id(),
        seq
    ))
}

const INDEX_PROJECTION_VERSION: &[u8] = b"sqlite-fts5-v1";

/// 从存储的 catalog payload 投影出可检索正文——rebuild 的规范投影函数。
///
/// 约定：现代 ingest/sync 写入的是完整 JSON payload（`{"role":..,"text":..,..}`），
/// 先尝试解析 JSON 取 `text` 字段；解析失败再回退历史格式——payload 里首个制表符
/// 之前是 role 前缀、之后是消息正文，无制表符则整体即正文（切片期 `index` 命令写入的
/// 无前缀纯文本）。因此仅凭 catalog 即可无损重建 FTS 投影，无需依赖可能已损坏/丢失的
/// 旧 FTS 内容。
///
/// 已知限制：切片期 `index` 命令若写入本身含制表符的正文，历史格式投影会截断到首个
/// 制表符之后——该命令仅供切片期测试，真实数据均经 ingest/sync 以 JSON payload 写入。
fn searchable_text(payload: &[u8]) -> String {
    // Modern shape: `{"role":...,"text":...,...}`. Indexing the raw JSON would
    // let structural tokens (`user`, `null`, `sessions`) match every message.
    if let Ok(value) = serde_json::from_slice::<serde_json::Value>(payload) {
        if let Some(text) = value.get("text").and_then(serde_json::Value::as_str) {
            return text.to_string();
        }
        // JSON that lacks a string `text` field must not fall back to
        // indexing the raw JSON (structural-token pollution). It carries no
        // searchable body.
        return String::new();
    }
    let text = String::from_utf8_lossy(payload);
    match text.split_once('\t') {
        Some((_role, body)) => body.to_string(),
        None => text.into_owned(),
    }
}

fn hash_field(hasher: &mut blake3::Hasher, bytes: &[u8]) {
    hasher.update(&(bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
}

/// Union two projections of the same message entity.
///
/// Claude Code copies a conversation's history into the new transcript when a
/// session is resumed or forked, so one message legitimately belongs to several
/// sessions. The `session` back-reference becomes a union (`sessions`, sorted,
/// with `session` kept as a single-value alias). The content projection
/// (`text`) is exempt from conflict authority too: a copy may carry a different
/// number of content blocks than the original (e.g. a truncated tool_result),
/// so the merged value deterministically keeps the longer projection and no
/// retrieved content is lost. `span`/`spans` are unioned keyed by contributing
/// document, and the contextual aliases (`parent`, `parent_native_id`,
/// `is_sidechain`, `seq`) may differ because they are regenerated from v7
/// relations once every contributing source is relation-complete. Only the
/// remaining stable fields must still agree byte-for-byte; a message whose
/// stable projection depends on which file it came from is a real
/// inconsistency and is still rejected.
fn merge_message_payloads(_wire: &str, left: &[u8], right: &[u8]) -> PortResult<Vec<u8>> {
    let parse = |bytes: &[u8]| -> PortResult<serde_json::Map<String, serde_json::Value>> {
        match serde_json::from_slice::<serde_json::Value>(bytes) {
            Ok(serde_json::Value::Object(map)) => Ok(map),
            // Slice-era rows hold bare text rather than canonical JSON. Those
            // cannot be reconciled field by field, so the conflict stands.
            _ => Err(PortError::Backend(
                "message has conflicting projections across sources".into(),
            )),
        }
    };

    let left_map = parse(left)?;
    let right_map = parse(right)?;

    let mut sessions: BTreeSet<String> = BTreeSet::new();
    // Spans are keyed by contributing document because the same message text
    // sits at different byte offsets in each file that carries it. Keying by
    // document also makes a re-sync idempotent: the same file always maps to
    // the same entry rather than appending a duplicate.
    let mut spans: BTreeMap<String, serde_json::Value> = BTreeMap::new();
    for map in [&left_map, &right_map] {
        if let Some(session) = map.get("session").and_then(|v| v.as_str()) {
            sessions.insert(session.to_string());
        }
        if let Some(list) = map.get("sessions").and_then(|v| v.as_array()) {
            for entry in list {
                if let Some(session) = entry.as_str() {
                    sessions.insert(session.to_string());
                }
            }
        }
        if let Some(list) = map.get("spans").and_then(|v| v.as_array()) {
            for entry in list {
                let Some(document) = entry.get("document").and_then(|v| v.as_str()) else {
                    return Err(PortError::Backend(
                        "message has a span without a document reference".into(),
                    ));
                };
                let document = document.to_string();
                // 同一 document 的多次出现按字段联合（右侧覆盖左侧）：保留左侧
                // 独有的字段——最典型的是 v7 再生回写的 `placement_id`——使 merge
                // 结果与再生后的 stored 逐字节一致，重同步才能收敛为内容级 no-op；
                // 偏移更新仍生效（右侧的 start/end 覆盖左侧）。
                match spans.get(&document).cloned() {
                    Some(mut existing) if entry.is_object() && existing.is_object() => {
                        let existing_obj = existing.as_object_mut().expect("checked is_object");
                        for (key, value) in entry.as_object().expect("checked is_object") {
                            existing_obj.insert(key.clone(), value.clone());
                        }
                        spans.insert(document, existing);
                    }
                    _ => {
                        spans.insert(document, entry.clone());
                    }
                }
            }
        }
    }

    // A row written before spans carried document attribution has only the
    // singular `span`. It cannot be keyed by document, so it is kept verbatim as
    // the alias rather than dropped — losing it would silently downgrade the
    // evidence for that message from byte precision to unknown.
    let legacy_span = [&left_map, &right_map]
        .into_iter()
        .find_map(|map| map.get("span").filter(|value| value.is_object()).cloned());

    // Only stable Message fields are conflict authority. Contextual compatibility
    // aliases may differ and are regenerated from v7 relations once every known
    // contributing source is relation-complete.
    for (a, b) in [(&left_map, &right_map), (&right_map, &left_map)] {
        for (key, value) in a {
            if matches!(
                key.as_str(),
                "session"
                    | "sessions"
                    | "span"
                    | "spans"
                    | "parent"
                    | "parent_native_id"
                    | "is_sidechain"
                    | "seq"
                    | "text"
            ) {
                continue;
            }
            if b.get(key) != Some(value) {
                // Codex's old adapter stored the occurrence-local outer
                // envelope timestamp as the message timestamp; the current
                // adapter emits no stable timestamp (different occurrences
                // carry different envelope timestamps). Re-ingesting such a
                // source therefore compares a string against null for the
                // same stable message, which must not be a conflict: the
                // merged value is null (no stable timestamp exists). A
                // missing key is treated like an explicit null for this
                // convergence.
                if key == "timestamp"
                    && matches!(
                        (value, b.get(key)),
                        (serde_json::Value::String(_), Some(serde_json::Value::Null))
                            | (serde_json::Value::Null, Some(serde_json::Value::String(_)))
                            | (serde_json::Value::String(_), None)
                            | (serde_json::Value::Null, None)
                    )
                {
                    continue;
                }
                return Err(PortError::Backend(
                    "message has conflicting projections across sources".into(),
                ));
            }
        }
    }

    // Timestamp is occurrence-local for Codex: an old adapter wrote the outer
    // envelope timestamp, the current one emits none. When projections disagree
    // on it (string vs null), converge deterministically on null regardless of
    // which projection happens to be on the left. A missing key is treated like
    // an explicit null for this convergence (the conflict check above already
    // treats them the same), so (string, missing) also converges to null
    // instead of keeping the string.
    let timestamp_states: [Option<bool>; 2] =
        [&left_map, &right_map].map(|map| map.get("timestamp").map(serde_json::Value::is_null));
    let timestamp_converges_to_null = timestamp_states
        .iter()
        .any(|state| matches!(state, Some(false)))
        && timestamp_states
            .iter()
            .any(|state| state.is_none_or(|is_null| is_null));

    let mut merged = left_map;
    if timestamp_converges_to_null {
        merged.insert("timestamp".to_string(), serde_json::Value::Null);
    }
    // `text` is a content projection, not a stable identity field: Claude Code
    // copies a conversation's history into the new transcript when a session is
    // resumed or forked, and a copy may carry a different number of content
    // blocks than the original (e.g. a truncated tool_result). The projections
    // legitimately differ, so text is exempt from conflict authority; the
    // merged value deterministically keeps the longer projection so no
    // retrieved content is lost.
    match (&merged.get("text"), right_map.get("text")) {
        (Some(left_text), Some(right_text)) => {
            let left_len = left_text.as_str().map_or(0, |s| s.len());
            let right_len = right_text.as_str().map_or(0, |s| s.len());
            if right_len > left_len {
                merged.insert("text".to_string(), right_text.clone());
            }
        }
        (None, Some(right_text)) => {
            merged.insert("text".to_string(), right_text.clone());
        }
        _ => {}
    }
    let sessions: Vec<String> = sessions.into_iter().collect();
    merged.insert(
        "session".to_string(),
        sessions
            .first()
            .cloned()
            .map_or(serde_json::Value::Null, serde_json::Value::String),
    );
    merged.insert("sessions".to_string(), serde_json::json!(sessions));

    let spans: Vec<serde_json::Value> = spans.into_values().collect();
    // `span` stays as a single-value alias holding the first contributing
    // document's offsets, so evidence assembly written against the pre-union
    // shape keeps reporting byte precision. On a message shared by several
    // files it names one location, not all of them.
    merged.insert(
        "span".to_string(),
        match spans.first() {
            Some(first) => serde_json::json!({
                "start": first.get("start").cloned().unwrap_or(serde_json::Value::Null),
                "end": first.get("end").cloned().unwrap_or(serde_json::Value::Null),
            }),
            None => legacy_span.unwrap_or(serde_json::Value::Null),
        },
    );
    merged.insert("spans".to_string(), serde_json::json!(spans));
    serde_json::to_vec(&serde_json::Value::Object(merged)).map_err(backend)
}

/// Union two projections of the same session container entity.
///
/// One logical session is routinely split across many transcript files, so each
/// source contributes only the members it actually carries. Merging appends the
/// right side's new members after the left side's and unions the contributing
/// documents. Both inputs must be canonical session JSON; a malformed stored
/// payload is a real inconsistency and is reported rather than silently
/// discarded.
///
/// Determinism comes from the caller: `sync` rejects duplicate source paths and
/// the CLI passes sources in a fixed order, so the same corpus yields the same
/// merged bytes and an unchanged re-sync still registers as a content-level
/// no-op.
fn merge_session_payloads(_wire: &str, left: &[u8], right: &[u8]) -> PortResult<Vec<u8>> {
    fn parse(bytes: &[u8]) -> PortResult<serde_json::Value> {
        serde_json::from_slice(bytes).map_err(|error| {
            PortError::Backend(format!("session payload is not canonical JSON: {error}"))
        })
    }

    let left_value = parse(left)?;
    let right_value = parse(right)?;

    // Member order is load-bearing: readers treat a member's position in this
    // array as its in-session sequence number, and branch selection picks the
    // highest-sequence non-sidechain leaf. Sorting by wire id would therefore
    // scramble conversation order for real provider-native ids, so the union is
    // append-only. `documents` carries no such meaning and is sorted.
    let mut members: Vec<String> = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut documents: BTreeSet<String> = BTreeSet::new();

    for value in [&left_value, &right_value] {
        // `document` (single) is the pre-union shape; `documents` (array) is what
        // a merged payload carries. Accept both so a store written by an older
        // binary merges cleanly instead of losing its attribution.
        if let Some(document) = value.get("document").and_then(|v| v.as_str()) {
            documents.insert(document.to_string());
        }
        if let Some(list) = value.get("documents").and_then(|v| v.as_array()) {
            for entry in list {
                if let Some(document) = entry.as_str() {
                    documents.insert(document.to_string());
                }
            }
        }
        let list = value
            .get("messages")
            .and_then(|v| v.as_array())
            .ok_or_else(|| PortError::Backend("session payload lacks a messages array".into()))?;
        for entry in list {
            let member = entry.as_str().ok_or_else(|| {
                PortError::Backend("session has a non-string message member".into())
            })?;
            if seen.insert(member.to_string()) {
                members.push(member.to_string());
            }
        }
    }

    let documents: Vec<String> = documents.into_iter().collect();
    let merged = serde_json::json!({
        // `document` stays as a single-value alias for the first contributing
        // document so readers written against the pre-union shape keep working.
        // On a multi-document session it names one contributor, not all of them.
        "document": documents.first().cloned(),
        "documents": documents,
        "messages": members,
    });
    serde_json::to_vec(&merged).map_err(backend)
}

/// One relation row to insert or replace in a relation-aware batch.
#[derive(Debug, Clone, PartialEq, Eq)]
enum RelationUpsertManifest {
    Placement(MessagePlacement),
    Edge(MessageEdge),
    Activity(StoredActivity),
}

impl RelationUpsertManifest {
    fn canonical_key(&self) -> String {
        match self {
            Self::Placement(placement) => format!("placement:{}", placement.id.as_str()),
            Self::Edge(edge) => format!("edge:{}", edge.child_placement_id.as_str()),
            Self::Activity(activity) => format!("activity:{}", activity.activity_id),
        }
    }

    fn canonical_value(&self) -> serde_json::Value {
        match self {
            Self::Placement(placement) => serde_json::json!({
                "kind": "message_placement",
                "placement": placement,
            }),
            Self::Edge(edge) => serde_json::json!({
                "kind": "message_edge",
                "edge": edge,
            }),
            Self::Activity(activity) => serde_json::json!({
                "kind": "tool_activity",
                "activity": {
                    "activity_id": activity.activity_id,
                    "message_id": activity.message_id,
                    "kind": activity.kind,
                    "actor": activity.actor,
                    "name": activity.name,
                    "target": activity.target,
                    "status": activity.status,
                },
            }),
        }
    }
}

/// One relation row to delete in a relation-aware batch.
#[derive(Debug, Clone, PartialEq, Eq)]
enum RelationDeleteManifest {
    Placement(PlacementId),
    Edge(PlacementId),
    Activity(String),
}

impl RelationDeleteManifest {
    fn canonical_key(&self) -> String {
        match self {
            Self::Placement(id) => format!("placement:{}", id.as_str()),
            Self::Edge(id) => format!("edge:{}", id.as_str()),
            Self::Activity(activity_id) => format!("activity:{activity_id}"),
        }
    }

    fn canonical_value(&self) -> serde_json::Value {
        match self {
            Self::Placement(id) => serde_json::json!({
                "kind": "message_placement",
                "placement_id": id,
            }),
            Self::Edge(id) => serde_json::json!({
                "kind": "message_edge",
                "child_placement_id": id,
            }),
            Self::Activity(activity_id) => serde_json::json!({
                "kind": "tool_activity",
                "activity_id": activity_id,
            }),
        }
    }
}

/// One durable source-to-entity membership row.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct SourceEntityMembershipManifest {
    entity_id: String,
    document_id: Option<String>,
}

impl SourceEntityMembershipManifest {
    fn canonical_value(&self) -> serde_json::Value {
        serde_json::json!({
            "entity_id": self.entity_id,
            "document_id": self.document_id,
        })
    }
}

/// Complete source-scoped state after applying one scan.
#[derive(Debug, Clone, PartialEq, Eq)]
struct SourceReplacementManifest {
    source_path: String,
    entity_memberships: Vec<SourceEntityMembershipManifest>,
    placement_ids: Vec<PlacementId>,
    /// 该源声明的工具活动 id（v12；按 activity_id 排序去重）。
    activity_ids: Vec<String>,
    relation_complete: bool,
    /// 捕获时源字节长度与内容指纹（source-scan 指纹缓存）。
    len_bytes: Option<i64>,
    fingerprint: Option<String>,
    /// 该 source 的 provider id；写入 `source_scans.provider_id` 供 discover diff。
    provider_id: Option<String>,
    /// Source-scoped Resume Metadata 声明（ADR-0009）：随本 source replacement
    /// 同事务原子写入；`None` = 该 source 无可声明值（清除旧声明）。
    resume_claim: Option<SourceResumeClaim>,
}

impl SourceReplacementManifest {
    fn canonical_value(&self) -> serde_json::Value {
        let mut entity_memberships = self.entity_memberships.clone();
        entity_memberships.sort();
        let entity_memberships: Vec<_> = entity_memberships
            .iter()
            .map(SourceEntityMembershipManifest::canonical_value)
            .collect();
        let mut placement_ids = self.placement_ids.clone();
        placement_ids.sort();
        let mut activity_ids = self.activity_ids.clone();
        activity_ids.sort();
        serde_json::json!({
            "source_path": self.source_path,
            "entity_memberships": entity_memberships,
            "placement_ids": placement_ids,
            "activity_ids": activity_ids,
            "relation_complete": self.relation_complete,
            "len_bytes": self.len_bytes,
            "fingerprint": self.fingerprint,
            "provider_id": self.provider_id,
            "resume_claim": self.resume_claim.as_ref().map(resume_claim_value),
        })
    }
}

/// Canonical JSON value of one [`SourceResumeClaim`]（含入 source replacement
/// 的 durable manifest：声明随 durable intent 一起哈希，改写声明即改写 digest）。
fn resume_claim_value(claim: &SourceResumeClaim) -> serde_json::Value {
    serde_json::json!({
        "provider_id": claim.provider_id,
        "session_id": claim.session_id,
        "provider_session_id": claim.provider_session_id,
        "provider_session_id_state": claim.provider_session_id_state,
        "original_working_directory": claim.original_working_directory,
        "original_working_directory_state": claim.original_working_directory_state,
        "pair_observed": claim.pair_observed,
    })
}

/// 持久化的 resume claim 行（`source_session_resume_claims` 表，ADR-0009）。
#[derive(Debug, Clone, PartialEq, Eq)]
struct StoredResumeClaim {
    session_id: String,
    provider_id: String,
    provider_session_id: Option<String>,
    provider_session_id_state: String,
    original_working_directory: Option<String>,
    original_working_directory_state: String,
    pair_observed: bool,
}

impl StoredResumeClaim {
    fn from_claim(claim: &SourceResumeClaim) -> Self {
        Self {
            session_id: claim.session_id.clone(),
            provider_id: claim.provider_id.clone(),
            provider_session_id: claim.provider_session_id.clone(),
            provider_session_id_state: claim.provider_session_id_state.clone(),
            original_working_directory: claim.original_working_directory.clone(),
            original_working_directory_state: claim.original_working_directory_state.clone(),
            pair_observed: claim.pair_observed,
        }
    }
}

/// 读取某 source 当前的 resume claim 行（写入路径保证每 source 至多一行）。
fn stored_resume_claim(
    conn: &Connection,
    source_path: &str,
) -> PortResult<Option<StoredResumeClaim>> {
    conn.query_row(
        "SELECT session_id, provider_id, provider_session_id, provider_session_id_state,
                original_working_directory, original_working_directory_state, pair_observed
         FROM source_session_resume_claims WHERE source_path = ?1",
        [source_path],
        |row| {
            Ok(StoredResumeClaim {
                session_id: row.get(0)?,
                provider_id: row.get(1)?,
                provider_session_id: row.get(2)?,
                provider_session_id_state: row.get(3)?,
                original_working_directory: row.get(4)?,
                original_working_directory_state: row.get(5)?,
                pair_observed: row.get(6)?,
            })
        },
    )
    .optional()
    .map_err(backend)
}

/// 把一条声明行解析为固定形状的 [`SessionResumeMetadata`]（fail closed）：
/// 只有 `provider_session_id_state == "resolved"` 且有值才算可恢复；missing/
/// ambiguous/无值一律不可恢复并给出简短 reason。字段取值以 state 为准——
/// 未 resolved 的字段即使携带值也按 None 输出，绝不把歧义值当权威值。
fn resume_metadata_from_claim(id: &StableId, claim: &StoredResumeClaim) -> SessionResumeMetadata {
    let available =
        claim.provider_session_id_state == "resolved" && claim.provider_session_id.is_some();
    let (provider_session_id, original_working_directory, unavailable_reason) = if available {
        let directory =
            if claim.original_working_directory_state == "resolved" && claim.pair_observed {
                claim.original_working_directory.clone()
            } else {
                None
            };
        (claim.provider_session_id.clone(), directory, None)
    } else {
        let reason = match claim.provider_session_id_state.as_str() {
            "missing" => "provider session id not observed",
            "ambiguous" => "ambiguous provider session id",
            "resolved" => "provider session id value missing",
            _ => "provider session id state unresolved",
        };
        (None, None, Some(reason.into()))
    };
    SessionResumeMetadata {
        session_id: id.clone(),
        provider_id: Some(claim.provider_id.clone()),
        resume_available: available,
        provider_session_id,
        original_working_directory,
        unavailable_reason,
    }
}

/// Canonical relation/source manifests stored beside the entity manifest.
#[derive(Debug, Clone, Default)]
struct RelationManifests {
    relation_upserts: Vec<RelationUpsertManifest>,
    relation_deletes: Vec<RelationDeleteManifest>,
    source_replacements: Vec<SourceReplacementManifest>,
}

impl RelationManifests {
    fn validate(&self) -> PortResult<()> {
        for upsert in &self.relation_upserts {
            match upsert {
                RelationUpsertManifest::Placement(placement) => {
                    validate_placement(placement)?;
                }
                RelationUpsertManifest::Edge(edge) => validate_edge(edge)?,
                // StoredActivity 在构造（stored_activity_from）时已完成
                // 领域校验与边界截断；此处只做清单结构校验（键唯一等）。
                RelationUpsertManifest::Activity(_) => {}
            }
        }
        let mut upsert_keys: Vec<_> = self
            .relation_upserts
            .iter()
            .map(RelationUpsertManifest::canonical_key)
            .collect();
        upsert_keys.sort();
        if upsert_keys.windows(2).any(|window| window[0] == window[1]) {
            return Err(PortError::Backend(
                "index batch contains duplicate relation upserts".into(),
            ));
        }

        let mut delete_keys: Vec<_> = self
            .relation_deletes
            .iter()
            .map(RelationDeleteManifest::canonical_key)
            .collect();
        delete_keys.sort();
        if delete_keys.windows(2).any(|window| window[0] == window[1]) {
            return Err(PortError::Backend(
                "index batch contains duplicate relation deletes".into(),
            ));
        }
        if upsert_keys
            .iter()
            .any(|key| delete_keys.binary_search(key).is_ok())
        {
            return Err(PortError::Backend(
                "index batch cannot upsert and delete the same relation".into(),
            ));
        }

        let mut source_paths: Vec<_> = self
            .source_replacements
            .iter()
            .map(|replacement| replacement.source_path.as_str())
            .collect();
        source_paths.sort_unstable();
        if source_paths.windows(2).any(|window| window[0] == window[1]) {
            return Err(PortError::Backend(
                "index batch contains duplicate source replacements".into(),
            ));
        }

        for replacement in &self.source_replacements {
            let mut entity_ids: Vec<_> = replacement
                .entity_memberships
                .iter()
                .map(|membership| membership.entity_id.as_str())
                .collect();
            entity_ids.sort_unstable();
            if entity_ids.windows(2).any(|window| window[0] == window[1]) {
                return Err(PortError::Backend(
                    "source replacement contains duplicate entity memberships".into(),
                ));
            }
            for membership in &replacement.entity_memberships {
                StableId::from_wire(&membership.entity_id).ok_or_else(|| {
                    PortError::Backend("source replacement has an invalid entity id".into())
                })?;
                if let Some(document_id) = &membership.document_id {
                    let document_id = StableId::from_wire(document_id).ok_or_else(|| {
                        PortError::Backend("source replacement has an invalid document id".into())
                    })?;
                    if document_id.kind() != IdKind::Document {
                        return Err(PortError::Backend(
                            "source membership document id has wrong kind".into(),
                        ));
                    }
                }
            }

            let mut placement_ids = replacement.placement_ids.clone();
            placement_ids.sort();
            if placement_ids
                .windows(2)
                .any(|window| window[0] == window[1])
            {
                return Err(PortError::Backend(
                    "source replacement contains duplicate placement claims".into(),
                ));
            }

            let mut activity_ids = replacement.activity_ids.clone();
            activity_ids.sort();
            if activity_ids.windows(2).any(|window| window[0] == window[1]) {
                return Err(PortError::Backend(
                    "source replacement contains duplicate activity claims".into(),
                ));
            }

            if let Some(claim) = &replacement.resume_claim {
                let claim_session = StableId::from_wire(&claim.session_id).ok_or_else(|| {
                    PortError::Backend(
                        "source replacement has an invalid resume claim session id".into(),
                    )
                })?;
                if claim_session.kind() != IdKind::Session {
                    return Err(PortError::Backend(
                        "source resume claim session id has wrong kind".into(),
                    ));
                }
                if !replacement
                    .entity_memberships
                    .iter()
                    .any(|membership| membership.entity_id == claim.session_id)
                {
                    return Err(PortError::Backend(
                        "source resume claim session does not belong to the source replacement"
                            .into(),
                    ));
                }
                if claim.provider_id.is_empty() {
                    return Err(PortError::Backend(
                        "source resume claim has an empty provider id".into(),
                    ));
                }
            }
        }
        Ok(())
    }

    fn canonical_json(&self) -> PortResult<(String, String, String)> {
        self.validate()?;
        let mut upserts: Vec<_> = self.relation_upserts.iter().collect();
        upserts.sort_by_key(|item| item.canonical_key());
        let upserts: Vec<_> = upserts
            .into_iter()
            .map(RelationUpsertManifest::canonical_value)
            .collect();

        let mut deletes: Vec<_> = self.relation_deletes.iter().collect();
        deletes.sort_by_key(|item| item.canonical_key());
        let deletes: Vec<_> = deletes
            .into_iter()
            .map(RelationDeleteManifest::canonical_value)
            .collect();

        let mut replacements: Vec<_> = self.source_replacements.iter().collect();
        replacements.sort_by(|left, right| left.source_path.cmp(&right.source_path));
        let replacements: Vec<_> = replacements
            .into_iter()
            .map(SourceReplacementManifest::canonical_value)
            .collect();

        Ok((
            serde_json::to_string(&upserts).map_err(backend)?,
            serde_json::to_string(&deletes).map_err(backend)?,
            serde_json::to_string(&replacements).map_err(backend)?,
        ))
    }
}

/// Canonical durable representation of one generation change set.
struct CanonicalBatchManifest {
    upsert_ids: Vec<String>,
    delete_ids: Vec<String>,
    relation_upserts_json: String,
    relation_deletes_json: String,
    source_replacements_json: String,
    operation_digest: String,
}

/// Canonicalize and fingerprint one generation change set.
///
/// Sorting by wire ID makes the digest independent of discovery order. Duplicate IDs and
/// upsert/delete overlap are rejected so the journal always describes an unambiguous set.
fn batch_manifest(
    upserts: &[(StableId, Vec<u8>, String)],
    deletes: &[StableId],
    relations: &RelationManifests,
) -> PortResult<CanonicalBatchManifest> {
    let mut ordered_upserts: Vec<_> = upserts.iter().collect();
    ordered_upserts.sort_by(|a, b| a.0.as_str().cmp(b.0.as_str()));
    let mut ordered_deletes: Vec<_> = deletes.iter().collect();
    ordered_deletes.sort_by(|a, b| a.as_str().cmp(b.as_str()));

    let upsert_ids: Vec<String> = ordered_upserts
        .iter()
        .map(|(id, _, _)| id.as_str().to_string())
        .collect();
    let delete_ids: Vec<String> = ordered_deletes
        .iter()
        .map(|id| id.as_str().to_string())
        .collect();
    if upsert_ids.windows(2).any(|w| w[0] == w[1]) || delete_ids.windows(2).any(|w| w[0] == w[1]) {
        return Err(PortError::Backend(
            "index batch contains duplicate entity ids".into(),
        ));
    }
    if upsert_ids
        .iter()
        .any(|id| delete_ids.binary_search(id).is_ok())
    {
        return Err(PortError::Backend(
            "index batch cannot upsert and delete the same entity".into(),
        ));
    }

    let mut hasher = blake3::Hasher::new();
    // 数据兼容性：分隔串刻意保留旧名 `agentsessions`——operation_digest 持久化在
    // index_batches 表并与既有 data root 中已存摘要交叉比对，改名会破坏 v7 数据兼容。
    hash_field(&mut hasher, b"agentsessions-index-batch-v1");
    hash_field(&mut hasher, INDEX_PROJECTION_VERSION);
    for (id, payload, text) in ordered_upserts {
        hash_field(&mut hasher, b"upsert");
        hash_field(&mut hasher, id.as_str().as_bytes());
        hash_field(&mut hasher, payload);
        hash_field(&mut hasher, text.as_bytes());
    }
    for id in ordered_deletes {
        hash_field(&mut hasher, b"delete");
        hash_field(&mut hasher, id.as_str().as_bytes());
    }

    let (relation_upserts_json, relation_deletes_json, source_replacements_json) =
        relations.canonical_json()?;
    hash_field(&mut hasher, b"relation_upserts");
    hash_field(&mut hasher, relation_upserts_json.as_bytes());
    hash_field(&mut hasher, b"relation_deletes");
    hash_field(&mut hasher, relation_deletes_json.as_bytes());
    hash_field(&mut hasher, b"source_replacements");
    hash_field(&mut hasher, source_replacements_json.as_bytes());

    Ok(CanonicalBatchManifest {
        upsert_ids,
        delete_ids,
        relation_upserts_json,
        relation_deletes_json,
        source_replacements_json,
        operation_digest: hasher.finalize().to_hex().to_string(),
    })
}

/// Durable outbox row for an index-generation operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexBatch {
    pub operation_id: String,
    pub base_generation: u64,
    pub target_generation: u64,
    pub state: String,
    pub operation_digest: String,
    pub upsert_ids: Vec<String>,
    pub delete_ids: Vec<String>,
    pub relation_upserts: Vec<serde_json::Value>,
    pub relation_deletes: Vec<serde_json::Value>,
    pub source_replacements: Vec<serde_json::Value>,
    pub durable_point: String,
    pub error_code: Option<String>,
}

/// Handle returned after an outbox intent reaches its first durable point.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingIndexBatch {
    pub operation_id: String,
    pub base_generation: u64,
    pub target_generation: u64,
    pub operation_digest: String,
}

/// 一个 source 完整成功 scan 后的全部消息条目。
///
/// `sync`/`ingest` 为每个只读源构造一个 `SourceBatch`，store 据此推导：本次出现的
/// message id 是 upsert；该源上次成功 scan 有、本次没有的 id 是 tombstone（删除）。
/// 只有整批全部源都 stage 成功后才提交；missing/tombstone 只能由完整成功 scan 确认。
#[derive(Clone)]
pub struct SourceBatch {
    /// 该源的稳定标识（当前用其只读路径字符串）。
    pub source_path: String,
    /// 本次 scan 得到的全部 (message id, catalog payload, 索引正文)。
    ///
    /// 自 v6 起，条目不限于消息：组合根把该源派生的 session（`ses_v1_*`）与
    /// document（`doc_v1_*`）目录实体放进同一批 entries，随消息走同一事务提交、
    /// 同一 membership/tombstone 推导——源消失时容器实体随消息一起退役。
    pub entries: Vec<(StableId, Vec<u8>, String)>,
    /// 本次 source scan 观察到的全部 contextual message occurrences。
    ///
    /// B1 只携带数据；B2 才会把这些关系写入 v7 表。
    pub placements: Vec<MessagePlacement>,
    /// 本次 source scan 观察到的全部 contextual parent edges。
    pub edges: Vec<MessageEdge>,
    /// 本次 source scan 观察到的全部工具活动（v12 投影；默认为空）。
    ///
    /// 活动锚定在 `message_id` 上；同一活动事实 + 同一锚点在不同源里派生同一
    /// activity_id（跨源副本去重，claims 计数决定行生命周期）。
    pub activities: Vec<SourceActivity>,
    /// 该 source 是否完成了零 skipped 的 relation scan。
    ///
    /// B1 不提交 completeness marker；B2 将据此替换或撤销 marker。
    pub relation_complete: bool,
    /// 捕获时的源字节长度与内容指纹（source-scan 指纹缓存，用于跳过
    /// 未变化源的重复解析）。None = 未提供（测试/旧调用方）。
    pub len_bytes: Option<i64>,
    pub fingerprint: Option<String>,
    /// Provider id supplied only by canonical-root discovery. Explicit sync batches
    /// leave this NULL so discover never tombstones paths outside its known root.
    pub provider_id: Option<String>,
    /// Source-scoped Resume Metadata 声明（ADR-0009）；随 source 事务原子写入，
    /// source 移除时同事务清除。`None` = 该 source 无可声明值。
    pub resume_claim: Option<SourceResumeClaim>,
}

/// 一条锚定在稳定消息上的工具活动（v12）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceActivity {
    pub message_id: StableId,
    pub activity: ToolActivity,
}

/// `tool_activities` 表行 + 活动 id 的存储视图。
#[derive(Debug, Clone, PartialEq, Eq)]
struct StoredActivity {
    activity_id: String,
    message_id: String,
    kind: String,
    actor: String,
    name: String,
    target: Option<String>,
    status: String,
}

impl StoredActivity {
    fn matches(&self, other: &StoredActivity) -> bool {
        self.message_id == other.message_id
            && self.kind == other.kind
            && self.actor == other.actor
            && self.name == other.name
            && self.target == other.target
            && self.status == other.status
    }
}

/// 工具名存储上限（字符数）：显式截断，防止 provider 失控的工具名膨胀存储。
const TOOL_ACTIVITY_NAME_MAX_CHARS: usize = 128;
/// 工具 target 存储上限（字符数）：显式截断；真实 transcript 的路径/命令
/// 可能很长，但活动只承载检索面事实，不需要全文。
const TOOL_ACTIVITY_TARGET_MAX_CHARS: usize = 512;

/// 内容寻址的活动 id：`act_v1_<hex16(blake3("tool-activity-v1" || …))>`。
///
/// 同一 (message_id, kind, actor, name, target, status) 派生同一 id——跨源副本
/// 天然去重；facts 在派生前已按存储上限截断（归一化点唯一，两侧一致）。
fn activity_id_for(message_id: &str, facts: &[&str]) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"tool-activity-v1");
    hasher.update(message_id.as_bytes());
    hasher.update(&[0]);
    for fact in facts {
        hasher.update(fact.as_bytes());
        hasher.update(&[0]);
    }
    let hex = hasher.finalize().to_hex();
    format!("act_v1_{}", &hex.as_str()[..16])
}

/// 把领域活动规范化为存储行（边界：显式截断 name/target；fail-closed 校验）。
fn stored_activity_from(
    message_id: &StableId,
    activity: &ToolActivity,
) -> PortResult<StoredActivity> {
    activity.validate().map_err(|error| {
        PortError::Backend(format!("tool activity violates domain invariants: {error}"))
    })?;
    if message_id.kind() != IdKind::Message {
        return Err(PortError::Backend(
            "tool activity message anchor has the wrong kind".into(),
        ));
    }
    let name: String = activity
        .name
        .chars()
        .take(TOOL_ACTIVITY_NAME_MAX_CHARS)
        .collect();
    let target = activity.target.as_deref().map(|target| {
        target
            .chars()
            .take(TOOL_ACTIVITY_TARGET_MAX_CHARS)
            .collect()
    });
    let row = StoredActivity {
        activity_id: activity_id_for(
            message_id.as_str(),
            &[
                activity.kind.as_str(),
                activity.actor.as_str(),
                &name,
                target.as_deref().unwrap_or(""),
                activity.status.as_str(),
            ],
        ),
        message_id: message_id.as_str().to_string(),
        kind: activity.kind.as_str().to_string(),
        actor: activity.actor.as_str().to_string(),
        name,
        target,
        status: activity.status.as_str().to_string(),
    };
    Ok(row)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StoredPlacement {
    session_id: String,
    document_id: String,
    message_id: String,
    source_ordinal: u32,
    is_sidechain: bool,
    span: Option<(u64, u64)>,
}

impl StoredPlacement {
    fn matches(&self, placement: &MessagePlacement) -> bool {
        self.session_id == placement.session_id.as_str()
            && self.document_id == placement.source_document_id.as_str()
            && self.message_id == placement.message_id.as_str()
            && self.source_ordinal == placement.source_ordinal
            && self.is_sidechain == placement.is_sidechain
            && self.span == placement.span.as_ref().map(|span| (span.start, span.end))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StoredEdge {
    parent_message_id: String,
    parent_native_id: Option<String>,
    relation: String,
}

impl StoredEdge {
    fn matches(&self, edge: &MessageEdge) -> bool {
        self.parent_message_id == edge.parent_message_id.as_str()
            && self.parent_native_id == edge.parent_native_id
            && self.relation == edge.relation.as_str()
    }
}

struct PreparedSource {
    relation_complete: bool,
    prior_entity_memberships: BTreeMap<String, Option<String>>,
    prior_placement_ids: BTreeSet<String>,
    prior_activity_ids: BTreeSet<String>,
    observed_placements: BTreeMap<String, MessagePlacement>,
    observed_edges: BTreeMap<String, MessageEdge>,
    replacement: SourceReplacementManifest,
}

fn validate_placement(placement: &MessagePlacement) -> PortResult<()> {
    if placement.session_id.kind() != IdKind::Session
        || placement.source_document_id.kind() != IdKind::Document
        || placement.message_id.kind() != IdKind::Message
    {
        return Err(PortError::Backend(
            "message placement contains an entity id with the wrong kind".into(),
        ));
    }
    let expected = PlacementId::derive(
        &placement.session_id,
        &placement.source_document_id,
        &placement.message_id,
        placement.source_ordinal,
    );
    if placement.id != expected {
        return Err(PortError::Backend(
            "message placement id does not match its contextual facts".into(),
        ));
    }
    if let Some(span) = &placement.span {
        if span.end < span.start {
            return Err(PortError::Backend(
                "message placement span end precedes start".into(),
            ));
        }
        i64::try_from(span.start).map_err(backend)?;
        i64::try_from(span.end).map_err(backend)?;
    }
    Ok(())
}

fn validate_edge(edge: &MessageEdge) -> PortResult<()> {
    if edge.parent_message_id.kind() != IdKind::Message {
        return Err(PortError::Backend(
            "message edge parent id has the wrong kind".into(),
        ));
    }
    Ok(())
}

fn stored_role(value: &str) -> PortResult<Role> {
    match value {
        "user" => Ok(Role::User),
        "assistant" => Ok(Role::Assistant),
        "system" => Ok(Role::System),
        // Codex's authoritative conversation role for the system/permission
        // layer; the codex adapter emits it verbatim (see provider-codex
        // is_conversational_role), so the read path must accept it.
        "developer" => Ok(Role::Developer),
        "tool" => Ok(Role::Tool),
        _ => Err(PortError::Backend(
            "stored message has an unsupported role".into(),
        )),
    }
}

fn stored_relation(value: &str) -> PortResult<MessageRelation> {
    match value {
        "reply" => Ok(MessageRelation::Reply),
        "retry" => Ok(MessageRelation::Retry),
        "fork" => Ok(MessageRelation::Fork),
        "continuation" => Ok(MessageRelation::Continuation),
        "subagent" => Ok(MessageRelation::Subagent),
        "tool_result" => Ok(MessageRelation::ToolResult),
        _ => Err(PortError::Backend(
            "stored message edge has an unsupported relation".into(),
        )),
    }
}

/// SQLite 支撑的存储：catalog 表存规范化实体负载，FTS5 表提供全文检索。
///
/// 单连接 + `RefCell` 内部可变：端口 trait 以 `&self` 取用，而 rusqlite 的写操作
/// 需要可变连接。首个垂直切片单线程使用，故不引入连接池。
///
/// 可选持有 [`WriterLease`]：经 [`SqliteStore::open_for_write`] 打开时，
/// lease 与 store 同生命周期，Drop store 时释放 data-root 写锁。
pub struct SqliteStore {
    conn: RefCell<Connection>,
    /// 写入路径持有的 data-root 独占 lease；只读打开时为 None。
    _lease: Option<WriterLease>,
    /// 当前语义模型 id（#3）：`None` 表示未配置语义检索，`SemanticIndex`
    /// 全部方法降级为空/未就绪。设置它是调用方声明"这些向量属于哪个模型"，
    /// 换模型后旧维度向量因 model_id 不匹配自然被排除。
    semantic_model_id: RefCell<Option<String>>,
}

/// 一批源路径的指纹缓存项：捕获时长度与内容指纹。
pub type SourceFingerprint = (Option<i64>, Option<String>);

impl SqliteStore {
    /// 只读打开（不抢 writer lease）。供 search/get/doctor 等读路径。
    pub fn open(path: &str) -> PortResult<Self> {
        let conn = Connection::open(path).map_err(backend)?;
        Self::init(&conn)?;
        Ok(SqliteStore {
            conn: RefCell::new(conn),
            _lease: None,
            semantic_model_id: RefCell::new(None),
        })
    }

    /// 写入路径打开：先在 db 所在目录获取 data-root writer lease，再打开库。
    ///
    /// 若另一进程已持 lease，立即失败（不阻塞）。lease 随本 store 存活，
    /// Drop 时释放，以维持每个 data root 单写者不变量。
    pub fn open_for_write(path: &str) -> PortResult<Self> {
        let db_path = Path::new(path);
        // 裸相对文件名（如 "catalog.db"）的 parent() 是空串 ""，create_dir_all("")
        // 会报错；空 parent 按当前工作目录处理（与只读 open 一致，目录解析交给
        // Connection::open / WriterLease）。
        let data_root = match db_path.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => parent,
            _ => Path::new("."),
        };
        let lease = WriterLease::try_acquire(data_root)?;
        let conn = Connection::open(path).map_err(backend)?;
        Self::init(&conn)?;
        let store = SqliteStore {
            conn: RefCell::new(conn),
            _lease: Some(lease),
            semantic_model_id: RefCell::new(None),
        };
        // lease 已到手，当前进程是唯一写者；安全收敛上次崩溃留下的无副作用 intent。
        store.recover_interrupted()?;
        Ok(store)
    }

    /// 打开内存存储（测试用，无 lease）。
    pub fn open_in_memory() -> PortResult<Self> {
        let conn = Connection::open_in_memory().map_err(backend)?;
        Self::init(&conn)?;
        Ok(SqliteStore {
            conn: RefCell::new(conn),
            _lease: None,
            semantic_model_id: RefCell::new(None),
        })
    }

    /// 打开并把 schema 迁移到当前版本，为版本化 migration 与可重建索引奠基。
    fn init(conn: &Connection) -> PortResult<()> {
        conn.execute_batch("PRAGMA journal_mode=WAL;")
            .map_err(backend)?;
        Self::migrate(conn)?;
        Self::register_scalar_functions(conn)
    }

    /// Register the ISO-8601 timestamp parser used by filtered search pushdown.
    ///
    /// `asg_instant_sort_key(text)` maps a timezone-qualified RFC3339/ISO-8601
    /// string to the 12-byte [`SearchInstant::sort_key`] BLOB (byte order ==
    /// instant order). Non-string inputs (e.g. Codex's modern `null`) and
    /// unparseable timestamps yield NULL so rows compare out of every
    /// half-open `[since, until)` predicate instead of erroring the query.
    fn register_scalar_functions(conn: &Connection) -> PortResult<()> {
        conn.create_scalar_function(
            "asg_instant_sort_key",
            1,
            rusqlite::functions::FunctionFlags::SQLITE_UTF8
                | rusqlite::functions::FunctionFlags::SQLITE_DETERMINISTIC,
            |ctx| {
                let value = ctx.get::<rusqlite::types::Value>(0)?;
                let rusqlite::types::Value::Text(text) = value else {
                    return Ok(None);
                };
                Ok(parse_search_instant(&text).map(|instant| instant.sort_key().to_vec()))
            },
        )
        .map_err(backend)
    }

    /// 按 `PRAGMA user_version` 门控的顺序迁移。
    ///
    /// 每次 schema 变更追加一个版本步骤并递增 [`SCHEMA_VERSION`]；旧库打开时
    /// 从其记录的版本逐步升级。`user_version` 是 SQLite 内建的每库整数，
    /// 不占额外表，正是 migration 追踪的标准落点。
    fn migrate(conn: &Connection) -> PortResult<()> {
        let current: i64 = conn
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .map_err(backend)?;
        if current > SCHEMA_VERSION {
            // 库比本二进制更新——拒绝而非静默降级，避免按旧 schema 误读新数据。
            return Err(PortError::SchemaIncompatible(format!(
                "catalog schema version {current} is newer than supported {SCHEMA_VERSION}; \
                 upgrade agent-session-grep or rebuild the data root"
            )));
        }
        let legacy_tx = if current < 6 {
            // v1-v6 are one atomic migration unit. A crash mid-way (e.g. after
            // source_membership's v5 rename but before user_version=6) must
            // roll back instead of stranding a store that can never reopen.
            Some(conn.unchecked_transaction().map_err(backend)?)
        } else {
            None
        };
        // Legacy steps run on the transaction when one was opened (its Deref
        // exposes the same Connection API); v7 migration keeps its own
        // transaction on the raw connection.
        let mig = legacy_tx.as_deref().unwrap_or(conn);
        if current < 1 {
            // v1：catalog（按 id 主键存 payload）+ contentful-id FTS5（id 回带，text 索引）。
            mig.execute_batch(
                "CREATE TABLE catalog (
                     id      TEXT PRIMARY KEY,
                     payload BLOB NOT NULL
                 );
                 CREATE VIRTUAL TABLE fts USING fts5(id UNINDEXED, text);",
            )
            .map_err(backend)?;
        }
        if current < 2 {
            // v2：活动 generation + durable outbox。FTS5 与 catalog 同事务提交，
            // journal 记录 intent、激活结果以及崩溃恢复结论。
            mig.execute_batch(
                "CREATE TABLE IF NOT EXISTS store_metadata (
                     singleton         INTEGER PRIMARY KEY CHECK(singleton = 1),
                     active_generation INTEGER NOT NULL CHECK(active_generation >= 0)
                 );
                 INSERT OR IGNORE INTO store_metadata(singleton, active_generation)
                 VALUES(1, 0);
                 CREATE TABLE IF NOT EXISTS index_batches (
                     operation_id     TEXT PRIMARY KEY,
                     base_generation  INTEGER NOT NULL,
                     target_generation INTEGER NOT NULL,
                     state            TEXT NOT NULL CHECK(state IN (
                         'building', 'search_built', 'activated', 'aborted',
                         'superseded', 'cleanup_pending'
                     )),
                     operation_digest TEXT NOT NULL,
                     upsert_ids_json  TEXT NOT NULL,
                     delete_ids_json  TEXT NOT NULL,
                     durable_point    TEXT NOT NULL,
                     created_at_ms    INTEGER NOT NULL,
                     committed_at_ms  INTEGER,
                     error_code       TEXT,
                     CHECK(target_generation = base_generation + 1)
                 );
                 CREATE INDEX IF NOT EXISTS index_batches_state
                 ON index_batches(state);",
            )
            .map_err(backend)?;
        }
        if current < 3 {
            // v3：以 wire id 为唯一索引键，隔离稳定性元数据，保证外部 wire round-trip
            // 形成的 Unstable id 也能删除原有 Native/Reconstructed FTS 行。
            mig.execute_batch(
                "CREATE TABLE IF NOT EXISTS fts_ids (
                     wire_id TEXT PRIMARY KEY,
                     id_json TEXT NOT NULL UNIQUE,
                     fts_rowid INTEGER
                 );",
            )
            .map_err(backend)?;
            let mut stmt = mig.prepare("SELECT id FROM fts").map_err(backend)?;
            let rows = stmt
                .query_map([], |row| row.get::<_, String>(0))
                .map_err(backend)?;
            let mut ids = Vec::new();
            for row in rows {
                let id_json = row.map_err(backend)?;
                let id: StableId = serde_json::from_str(&id_json).map_err(backend)?;
                ids.push((id.as_str().to_string(), id_json));
            }
            drop(stmt);
            for (wire_id, id_json) in ids {
                mig.execute(
                    "INSERT OR REPLACE INTO fts_ids(wire_id, id_json) VALUES(?1, ?2)",
                    rusqlite::params![wire_id, id_json],
                )
                .map_err(backend)?;
            }
        }
        if current < 4 {
            // v4：记录每个 source 最近一次完整成功 scan 的 message membership，
            // 只有完整 scan 成功后才可安全推导删除/tombstone。
            mig.execute_batch(
                "CREATE TABLE IF NOT EXISTS source_membership (
                     source_path TEXT NOT NULL,
                     message_id  TEXT PRIMARY KEY
                 );
                 CREATE INDEX IF NOT EXISTS source_membership_source
                 ON source_membership(source_path);",
            )
            .map_err(backend)?;
        }
        if current < 5 {
            // v5：空 source scan 也必须留下“已成功扫描”的证据；membership 改为
            // 多对多主键，避免删除一个 source 时误删仍被其它 source 引用的实体。
            mig.execute_batch(
                "DROP INDEX IF EXISTS source_membership_source;
                 ALTER TABLE source_membership RENAME TO source_membership_v4;
                 CREATE TABLE source_membership (
                     source_path TEXT NOT NULL,
                     message_id  TEXT NOT NULL,
                     PRIMARY KEY(source_path, message_id)
                 );
                 INSERT INTO source_membership(source_path, message_id)
                 SELECT source_path, message_id FROM source_membership_v4;
                 DROP TABLE source_membership_v4;
                 CREATE INDEX source_membership_source
                 ON source_membership(source_path);
                 CREATE TABLE IF NOT EXISTS source_scans (
                     source_path   TEXT PRIMARY KEY,
                     scanned_at_ms INTEGER NOT NULL,
                     len_bytes     INTEGER,
                     fingerprint   TEXT,
                     provider_id   TEXT
                 );",
            )
            .map_err(backend)?;
        }
        if current < 6 {
            // v6：source_membership 增加可空 document_id——记录各 source 所属文档实体的
            // wire id，使 source 消失的 tombstone 清理能同步退役其 session/document 目录行。
            // 旧行保持 NULL（v6 前的 membership 无文档归属信息）。
            let has_document_id = mig
                .prepare("PRAGMA table_info(source_membership)")
                .map_err(backend)?
                .query_map([], |row| row.get::<_, String>(1))
                .map_err(backend)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(backend)?
                .iter()
                .any(|name| name == "document_id");
            if !has_document_id {
                mig.execute_batch("ALTER TABLE source_membership ADD COLUMN document_id TEXT;")
                    .map_err(backend)?;
            }
            // Commit the versioned steps before the atomic v6->v7 step, which
            // opens its own transaction on the raw connection.
            mig.execute_batch("PRAGMA user_version = 6;")
                .map_err(backend)?;
            if let Some(tx) = legacy_tx {
                tx.commit().map_err(backend)?;
            }
        }
        if current < 7 {
            Self::migrate_v6_to_v7(conn)?;
        }
        if current < 8 {
            Self::migrate_v7_to_v8(conn)?;
        }
        if current < 9 {
            Self::migrate_v8_to_v9(conn)?;
        }
        if current < 10 {
            Self::migrate_v9_to_v10(conn)?;
        }
        if current < 11 {
            Self::migrate_v10_to_v11(conn)?;
        }
        if current < 12 {
            Self::migrate_v11_to_v12(conn)?;
        }
        // 不随 user_version 门控：旧 v7 库（本列存在前建成的）打开时同样需要。
        Self::ensure_fts_ids_rowid(conn)?;
        Ok(())
    }

    /// 确保 `fts_ids` 边车携带 `fts_rowid` 列（v7 内的加法扩展，`user_version` 不变）。
    ///
    /// FTS5 表的 `id` 列是内容列而非 rowid，旧删除语句按内容比较会整表扫描
    /// （`SCAN fts VIRTUAL TABLE INDEX 0`），每批提交成本 O(全库)。本列把
    /// fts5 行的 rowid 回写到边车，删除改按 rowid 定位（O(1)）。
    /// 新库在 v3 建表时已带本列，此处直接短路——open（含只读 open）不再为
    /// 新库执行 ALTER+回填事务；只有 fts_rowid 列加入前建成的旧 v7 库首次
    /// 打开时走 ALTER+回填：`fts` 与 `fts_ids` 自 v3 起同事务写入、一一对应，
    /// 用 `id_json` 连接即可把 fts5 已分配的行 rowid 抄进边车；session/document
    /// 实体无 fts 行，保持 NULL（删除按 NULL 定位即无操作）。
    /// ALTER 与回填在同一事务内，崩溃不留半成品；重跑因列已存在直接短路。
    /// 并发打开旧库时 ALTER/回填可能遇 BUSY/LOCKED——经 [`backend`] 归一为
    /// 可重试的 WriterBusy，调用方应重试而非当作锁损坏。
    fn ensure_fts_ids_rowid(conn: &Connection) -> PortResult<()> {
        let has_fts_rowid = conn
            .prepare("PRAGMA table_info(fts_ids)")
            .map_err(backend)?
            .query_map([], |row| row.get::<_, String>(1))
            .map_err(backend)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(backend)?
            .iter()
            .any(|name| name == "fts_rowid");
        if has_fts_rowid {
            return Ok(());
        }
        let tx = conn.unchecked_transaction().map_err(backend)?;
        tx.execute_batch("ALTER TABLE fts_ids ADD COLUMN fts_rowid INTEGER;")
            .map_err(backend)?;
        let rows: Vec<(String, i64)> = {
            let mut stmt = tx
                .prepare(
                    "SELECT fi.wire_id, f.rowid
                     FROM fts f JOIN fts_ids fi ON fi.id_json = f.id",
                )
                .map_err(backend)?;
            let mapped = stmt
                .query_map([], |row| {
                    let wire: String = row.get(0)?;
                    let rid: i64 = row.get(1)?;
                    Ok((wire, rid))
                })
                .map_err(backend)?;
            let mut out = Vec::new();
            for row in mapped {
                out.push(row.map_err(backend)?);
            }
            out
        };
        for (wire_id, fts_rowid) in rows {
            tx.execute(
                "UPDATE fts_ids SET fts_rowid = ?2 WHERE wire_id = ?1",
                rusqlite::params![wire_id, fts_rowid],
            )
            .map_err(backend)?;
        }
        tx.commit().map_err(backend)?;
        Ok(())
    }

    /// Add the v7 relational schema in one explicit transaction.
    ///
    /// Legacy catalog and source-membership rows are retained byte-for-byte.
    /// No placement, edge, source claim, or relation-complete marker can be
    /// reconstructed safely from v6 aliases, so all new relation tables start
    /// empty. `user_version = 7` is part of the same transaction as the DDL.
    fn migrate_v6_to_v7(conn: &Connection) -> PortResult<()> {
        Self::migrate_v6_to_v7_inner(conn, false)
    }

    fn migrate_v6_to_v7_inner(conn: &Connection, inject_failure: bool) -> PortResult<()> {
        let tx = conn.unchecked_transaction().map_err(backend)?;
        tx.execute_batch(
            "CREATE TABLE message_placements (
                 placement_id   TEXT PRIMARY KEY,
                 session_id     TEXT NOT NULL,
                 document_id    TEXT NOT NULL,
                 message_id     TEXT NOT NULL,
                 source_ordinal INTEGER NOT NULL CHECK(source_ordinal >= 0),
                 is_sidechain   INTEGER NOT NULL CHECK(is_sidechain IN (0, 1)),
                 byte_start     INTEGER,
                 byte_end       INTEGER,
                 CHECK(
                     (byte_start IS NULL AND byte_end IS NULL)
                     OR (byte_start >= 0 AND byte_end >= byte_start)
                 ),
                 UNIQUE(session_id, document_id, source_ordinal)
             );
             CREATE TABLE message_edges (
                 child_placement_id TEXT PRIMARY KEY,
                 parent_message_id  TEXT NOT NULL,
                 parent_native_id   TEXT,
                 relation           TEXT NOT NULL
             );
             CREATE TABLE source_placement_membership (
                 source_path  TEXT NOT NULL,
                 placement_id TEXT NOT NULL,
                 PRIMARY KEY(source_path, placement_id)
             );
             CREATE TABLE source_relation_scans (
                 source_path             TEXT PRIMARY KEY,
                 relation_schema_version INTEGER NOT NULL
                     CHECK(relation_schema_version >= 7)
             );
             CREATE INDEX message_placements_session_order
             ON message_placements(session_id, document_id, source_ordinal, placement_id);
             CREATE INDEX message_placements_message
             ON message_placements(message_id);
             CREATE INDEX message_placements_document
             ON message_placements(document_id);
             CREATE INDEX source_placement_membership_placement
             ON source_placement_membership(placement_id);
             ALTER TABLE index_batches
             ADD COLUMN relation_upserts_json TEXT NOT NULL DEFAULT '[]';
             ALTER TABLE index_batches
             ADD COLUMN relation_deletes_json TEXT NOT NULL DEFAULT '[]';
             ALTER TABLE index_batches
             ADD COLUMN source_replacements_json TEXT NOT NULL DEFAULT '[]';
             PRAGMA user_version = 7;",
        )
        .map_err(backend)?;

        // Source-scan fingerprint cache columns (additive within v7): used by
        // the CLI to skip re-parsing sources whose bytes are unchanged.
        // Idempotent for catalogs that reached v7 before these columns
        // existed.
        let has_len_bytes: bool = tx
            .prepare("PRAGMA table_info(source_scans)")
            .map_err(backend)?
            .query_map([], |row| row.get::<_, String>(1))
            .map_err(backend)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(backend)?
            .iter()
            .any(|name| name == "len_bytes");
        if !has_len_bytes {
            tx.execute_batch(
                "ALTER TABLE source_scans ADD COLUMN len_bytes INTEGER;
                 ALTER TABLE source_scans ADD COLUMN fingerprint TEXT;",
            )
            .map_err(backend)?;
        }

        if inject_failure {
            return Err(PortError::Backend(
                "injected v6-to-v7 migration failure".into(),
            ));
        }

        tx.commit().map_err(backend)
    }

    /// Add the v8 resume-claims schema in one explicit transaction.
    ///
    /// Source-scoped Resume Metadata claims (ADR-0009)：键为
    /// `(source_path, session_id)`，随派生它们的 source replacement 同事务
    /// 原子写入/替换，source 移除时同事务清除。声明是独立的只读解析源，
    /// 不进入 FTS 正文；legacy 库迁到 v8 后表为空，所有 session 读到
    /// "no resume metadata claims"（不可恢复），直至 re-sync 回填声明。
    /// `user_version = 8` 与 DDL 在同一事务内。
    fn migrate_v7_to_v8(conn: &Connection) -> PortResult<()> {
        Self::migrate_v7_to_v8_inner(conn, false)
    }

    fn migrate_v7_to_v8_inner(conn: &Connection, inject_failure: bool) -> PortResult<()> {
        let tx = conn.unchecked_transaction().map_err(backend)?;
        tx.execute_batch(
            "CREATE TABLE source_session_resume_claims (
                 source_path                      TEXT NOT NULL,
                 session_id                       TEXT NOT NULL,
                 provider_id                      TEXT NOT NULL,
                 provider_session_id              TEXT,
                 provider_session_id_state        TEXT NOT NULL,
                 original_working_directory       TEXT,
                 original_working_directory_state TEXT NOT NULL,
                 pair_observed                    INTEGER NOT NULL
                     CHECK(pair_observed IN (0, 1)),
                 PRIMARY KEY(source_path, session_id)
             );
             CREATE INDEX source_session_resume_claims_session
             ON source_session_resume_claims(session_id, source_path);
             PRAGMA user_version = 8;",
        )
        .map_err(backend)?;

        if inject_failure {
            return Err(PortError::Backend(
                "injected v7-to-v8 migration failure".into(),
            ));
        }

        tx.commit().map_err(backend)
    }

    /// Add the v9 `provider_id` column to `source_scans` (additive, non-destructive).
    ///
    /// `sync --discover` 用 `provider_id` 按 provider diff 已存源路径：找出某个
    /// provider 下曾被扫描、本次未在磁盘上出现的源，合成空批 tombstone（仅在
    /// 完整扫描时）。旧行保持 NULL（直到该源被再次扫描时回填）。列存在即无害：
    /// 未升级的 v8 代码路径忽略它。
    fn migrate_v8_to_v9(conn: &Connection) -> PortResult<()> {
        let has_provider_id = conn
            .prepare("PRAGMA table_info(source_scans)")
            .map_err(backend)?
            .query_map([], |row| row.get::<_, String>(1))
            .map_err(backend)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(backend)?
            .iter()
            .any(|name| name == "provider_id");
        if has_provider_id {
            // 已有列（可能是本迁移重跑或新库建表时已带）；只对齐 user_version。
            conn.execute_batch("PRAGMA user_version = 9;")
                .map_err(backend)?;
            return Ok(());
        }
        let tx = conn.unchecked_transaction().map_err(backend)?;
        tx.execute_batch(
            "ALTER TABLE source_scans ADD COLUMN provider_id TEXT;
             PRAGMA user_version = 9;",
        )
        .map_err(backend)?;
        tx.commit().map_err(backend)
    }

    /// v9→v10：语义向量边车表（#3）。
    ///
    /// `message_vec` 与 `fts` 同级——都是 catalog 的可重建投影，不是权威数据。
    /// 向量以 little-endian f32 blob 存储（`dimension` 显式记录，避免读回时
    /// 靠 blob 长度推断）；`model_id` 让换模型后的旧向量可被识别并清理，而不是
    /// 与新维度向量混在一张表里静默产生垃圾相似度。
    /// 主键是 wire_id：与 `fts_ids` 同一连接键，删除路径无需第二套 id 映射。
    fn migrate_v9_to_v10(conn: &Connection) -> PortResult<()> {
        let tx = conn.unchecked_transaction().map_err(backend)?;
        tx.execute_batch(
            "CREATE TABLE IF NOT EXISTS message_vec (
                 wire_id   TEXT PRIMARY KEY,
                 model_id  TEXT NOT NULL,
                 dimension INTEGER NOT NULL CHECK(dimension > 0),
                 embedding BLOB NOT NULL
             );
             CREATE INDEX IF NOT EXISTS message_vec_model ON message_vec(model_id);
             PRAGMA user_version = 10;",
        )
        .map_err(backend)?;
        tx.commit().map_err(backend)
    }

    /// Add the v11 privacy-safe Session metadata search projection.
    ///
    /// Both tables are derived state: `session_fts` holds only bounded, resolved
    /// Session metadata and `session_fts_ids` maps the canonical Session wire to
    /// the FTS rowid. Existing catalog, message FTS, claims, and relations remain
    /// untouched; rebuild or the next affected source commit populates the new
    /// projection for migrated databases.
    fn migrate_v10_to_v11(conn: &Connection) -> PortResult<()> {
        let tx = conn.unchecked_transaction().map_err(backend)?;
        tx.execute_batch(
            "CREATE VIRTUAL TABLE IF NOT EXISTS session_fts USING fts5(session_wire UNINDEXED, text);
             CREATE TABLE IF NOT EXISTS session_fts_ids (
                 session_wire TEXT PRIMARY KEY,
                 fts_rowid    INTEGER NOT NULL
             );
             PRAGMA user_version = 11;",
        )
        .map_err(backend)?;
        tx.commit().map_err(backend)
    }

    /// Add the v12 tool-activity projection in one explicit transaction
    /// (additive, non-destructive).
    ///
    /// `tool_activities` stores typed tool-call observations anchored to stable
    /// message wire ids; `tool_activity_membership` records per-source claims so
    /// the lifecycle mirrors `message_placements` (complete-scan replace,
    /// incomplete-scan union, tombstone via claims). The step depends only on
    /// v7+ tables, so it runs cleanly on any catalog at v7..=11 — merge-safe
    /// with parallel schema branches. `user_version = 12` commits with the DDL.
    fn migrate_v11_to_v12(conn: &Connection) -> PortResult<()> {
        let tx = conn.unchecked_transaction().map_err(backend)?;
        tx.execute_batch(
            "CREATE TABLE IF NOT EXISTS tool_activities (
                 activity_id TEXT PRIMARY KEY,
                 message_id  TEXT NOT NULL,
                 kind        TEXT NOT NULL,
                 actor       TEXT NOT NULL,
                 name        TEXT NOT NULL,
                 target      TEXT,
                 status      TEXT NOT NULL
             );
             CREATE INDEX IF NOT EXISTS tool_activities_message ON tool_activities(message_id);
             CREATE INDEX IF NOT EXISTS tool_activities_kind ON tool_activities(kind);
             CREATE INDEX IF NOT EXISTS tool_activities_name ON tool_activities(name);
             CREATE TABLE IF NOT EXISTS tool_activity_membership (
                 source_path TEXT NOT NULL,
                 activity_id TEXT NOT NULL,
                 PRIMARY KEY(source_path, activity_id)
             );
             CREATE INDEX IF NOT EXISTS tool_activity_membership_activity
             ON tool_activity_membership(activity_id);
             PRAGMA user_version = 12;",
        )
        .map_err(backend)?;
        tx.commit().map_err(backend)
    }

    /// 声明语义向量归属的模型 id（#3）。未设置时 `SemanticIndex` 全部方法
    /// 视为未配置：`is_ready` 为 false、查询返回空、写入报错——这样"忘了配模型"
    /// 不会变成往表里写无归属向量。
    pub fn set_semantic_model(&self, model_id: impl Into<String>) {
        *self.semantic_model_id.borrow_mut() = Some(model_id.into());
    }

    /// 清除当前模型下的全部向量（换模型或 rebuild 语义索引时使用）。
    /// 返回删除行数。向量表是投影而非权威数据，清除永不影响 catalog。
    pub fn clear_embeddings(&self, model_id: &str) -> PortResult<usize> {
        let conn = self.conn.borrow();
        let n = conn
            .execute("DELETE FROM message_vec WHERE model_id = ?1", [model_id])
            .map_err(backend)?;
        Ok(n)
    }

    /// Batch-load role + sidechain facts for the given message wire ids.
    ///
    /// Role comes from the canonical message payload; sidechain is true when
    /// the message has at least one `message_placements.is_sidechain = 1` row.
    /// Missing messages are omitted (caller treats absence as unknown/false).
    pub fn message_facts_for(
        &self,
        message_ids: &[StableId],
    ) -> PortResult<Vec<(String, String, bool)>> {
        if message_ids.is_empty() {
            return Ok(Vec::new());
        }
        let conn = self.conn.borrow();
        let wires: Vec<&str> = message_ids.iter().map(|id| id.as_str()).collect();
        let mut out = Vec::new();
        for chunk in chunk_ids(&wires) {
            let placeholders = chunk.iter().map(|_| "?").collect::<Vec<_>>().join(",");
            // Role from catalog payload JSON; sidechain via EXISTS on placements.
            let mut stmt = conn
                .prepare(&format!(
                    "SELECT c.id,
                            COALESCE(json_extract(c.payload, '$.role'), 'unknown'),
                            EXISTS(
                              SELECT 1 FROM message_placements mp
                              WHERE mp.message_id = c.id AND mp.is_sidechain = 1
                            )
                     FROM catalog c
                     WHERE c.id IN ({placeholders})
                     ORDER BY c.id"
                ))
                .map_err(backend)?;
            let rows = stmt
                .query_map(rusqlite::params_from_iter(chunk.iter().copied()), |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)? != 0,
                    ))
                })
                .map_err(backend)?;
            for row in rows {
                out.push(row.map_err(backend)?);
            }
        }
        Ok(out)
    }

    /// Batch-load tool activities for the given message wire ids (handoff pack).
    ///
    /// Returns one JSON object per activity, stable-ordered by
    /// `(message_id, activity_id)`. Unknown message ids contribute nothing.
    pub fn tool_activities_for_messages(
        &self,
        message_ids: &[StableId],
    ) -> PortResult<Vec<serde_json::Value>> {
        if message_ids.is_empty() {
            return Ok(Vec::new());
        }
        let conn = self.conn.borrow();
        let wires: Vec<&str> = message_ids.iter().map(|id| id.as_str()).collect();
        let mut out = Vec::new();
        for chunk in chunk_ids(&wires) {
            let placeholders = chunk.iter().map(|_| "?").collect::<Vec<_>>().join(",");
            let mut stmt = conn
                .prepare(&format!(
                    "SELECT activity_id, message_id, kind, actor, name, target, status
                     FROM tool_activities
                     WHERE message_id IN ({placeholders})
                     ORDER BY message_id, activity_id"
                ))
                .map_err(backend)?;
            let rows = stmt
                .query_map(rusqlite::params_from_iter(chunk.iter().copied()), |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, Option<String>>(5)?,
                        row.get::<_, String>(6)?,
                    ))
                })
                .map_err(backend)?;
            for row in rows {
                let (activity_id, message_id, kind, actor, name, target, status) =
                    row.map_err(backend)?;
                out.push(serde_json::json!({
                    "activity_id": activity_id,
                    "message_id": message_id,
                    "kind": kind,
                    "actor": actor,
                    "name": name,
                    "target": target,
                    "status": status,
                }));
            }
        }
        Ok(out)
    }

    /// v12 工具活动投影的孤儿扫描（只读，doctor/维护证据）：
    /// 返回 `(孤儿活动行数, 孤儿成员行数)`。
    ///
    /// - 孤儿活动：`tool_activities` 行没有对应的 catalog 消息行。活动是消息
    ///   的投影，消息退役时其活动由 claims 推导同事务删除（见
    ///   [`commit_source_batches_if_changed`]）；残余行是投影漂移证据。
    /// - 孤儿成员：`tool_activity_membership` 行指向不存在的活动（悬空 claim）。
    ///
    /// 两类行都无法再从 catalog 重建，是确定性修剪
    /// （[`purge_orphaned_activities`](Self::purge_orphaned_activities)）的输入。
    pub fn orphaned_activity_counts(&self) -> PortResult<(u64, u64)> {
        let conn = self.conn.borrow();
        let activities: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM tool_activities ta
                 WHERE NOT EXISTS (
                     SELECT 1 FROM catalog c WHERE c.id = ta.message_id
                 )",
                [],
                |row| row.get(0),
            )
            .map_err(backend)?;
        let memberships: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM tool_activity_membership m
                 WHERE NOT EXISTS (
                     SELECT 1 FROM tool_activities ta
                     WHERE ta.activity_id = m.activity_id
                 )",
                [],
                |row| row.get(0),
            )
            .map_err(backend)?;
        Ok((
            u64::try_from(activities).map_err(backend)?,
            u64::try_from(memberships).map_err(backend)?,
        ))
    }

    /// 确定性修剪孤儿工具活动行（v12 保留策略的维护路径）。
    ///
    /// 活动是 catalog 的投影：正常写入路径里，source 退役与消息 tombstone 会
    /// 在同一事务内推导并删除其活动与 claim；本方法只删除漂移残余——没有
    /// catalog 消息的活动行、指向不存在活动的成员行——绝不触碰仍锚定在
    /// catalog 消息上的活动及其合法 claim，也不触碰 catalog/FTS/session 元数据。
    ///
    /// 与 [`rebuild_index`](Self::rebuild_index) 同一 writer 纪律：durable
    /// intent（CAS base generation）→ 单事务校验 + 删除 + 推进 generation +
    /// activate，outbox 行即本次维护操作的审计记录。返回 `(删除活动行数,
    /// 删除成员行数)`——成员行数含随孤儿活动删除而级联清除的 claim。无孤儿时
    /// 不写库（返回 `(0, 0)`，generation 不动）——修剪是收敛操作，空跑不
    /// 产生 journal churn。
    pub fn purge_orphaned_activities(&self) -> PortResult<(u64, u64)> {
        let (activities, memberships) = self.orphaned_activity_counts()?;
        if activities == 0 && memberships == 0 {
            return Ok((0, 0));
        }
        // 空变更集的 durable intent：与 rebuild 同一条 CAS 前置条件
        // （active_generation == base），防止并发写者抢先推进后误修剪。
        let pending = self.begin_index_batch(&[], &[])?;
        let mut conn = self.conn.borrow_mut();
        let tx = conn.transaction().map_err(backend)?;
        Self::verify_pending_in_tx(&tx, &pending, &[], &[], &RelationManifests::default())?;
        // 确定性删除：谓词自包含，只删事务时刻仍然悬空的行（与扫描同一谓词）。
        // 先删孤儿活动行，再清悬空 claim——claim 的悬空定义是"指向不存在的
        // 活动"，第二个语句同时覆盖预先悬空的 claim 与刚删活动的 claim；
        // 反序会在删除活动后留下新悬空 claim。
        let removed_activities = tx
            .execute(
                "DELETE FROM tool_activities
                 WHERE NOT EXISTS (
                     SELECT 1 FROM catalog c WHERE c.id = tool_activities.message_id
                 )",
                [],
            )
            .map_err(backend)?;
        let removed_memberships = tx
            .execute(
                "DELETE FROM tool_activity_membership
                 WHERE activity_id NOT IN (SELECT activity_id FROM tool_activities)",
                [],
            )
            .map_err(backend)?;
        tx.execute(
            "UPDATE store_metadata SET active_generation = ?1 WHERE singleton = 1",
            [pending.target_generation as i64],
        )
        .map_err(backend)?;
        tx.execute(
            "UPDATE index_batches
             SET state = 'activated', durable_point = 'activated', committed_at_ms = ?2
             WHERE operation_id = ?1",
            rusqlite::params![pending.operation_id, unix_ms()?],
        )
        .map_err(backend)?;
        tx.commit().map_err(backend)?;
        Ok((
            u64::try_from(removed_activities).map_err(backend)?,
            u64::try_from(removed_memberships).map_err(backend)?,
        ))
    }

    /// 当前存储读回的 schema 版本（供 doctor/诊断）。
    pub fn schema_version(&self) -> PortResult<i64> {
        self.conn
            .borrow()
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .map_err(backend)
    }

    /// 按 wire id 升序分页列出 catalog 实体；`kind` 为 `Some` 时只返回该 kind
    /// 的实体（SQL 前缀过滤，使 offset/limit 作用于过滤后的集合——见
    /// `CatalogStore::list_sessions` 的分页语义约束）。
    fn list_filtered(
        conn: &RefCell<Connection>,
        kind: Option<IdKind>,
        limit: usize,
    ) -> PortResult<Vec<CatalogEntry>> {
        let conn = conn.borrow();
        // 前缀是受控常量（`ses_v1_` 等），拼进 SQL 不会引入注入面；避免按
        // `? IS NULL OR id LIKE ?` 形式传参，让查询规划器对两种形状都走索引。
        let sql = match kind {
            Some(kind) => format!(
                "SELECT id, payload FROM catalog WHERE id LIKE '{}%' ORDER BY id ASC LIMIT ?1",
                kind.prefix()
            ),
            None => "SELECT id, payload FROM catalog ORDER BY id ASC LIMIT ?1".to_string(),
        };
        let mut stmt = conn.prepare(&sql).map_err(backend)?;
        let rows = stmt
            .query_map([limit as i64], |row| {
                let wire: String = row.get(0)?;
                let payload: Vec<u8> = row.get(1)?;
                Ok((wire, payload))
            })
            .map_err(backend)?;
        let mut entries = Vec::new();
        for row in rows {
            let (wire, payload) = row.map_err(backend)?;
            let id = StableId::from_wire(&wire).ok_or_else(|| {
                PortError::Backend("catalog contains an invalid entity id".into())
            })?;
            entries.push(CatalogEntry { id, payload });
        }
        Ok(entries)
    }

    /// 读取一批源路径的指纹缓存（source_scans 的 len/fingerprint 列）。
    ///
    /// 返回 `path -> (len_bytes, fingerprint)`；从未扫描过的源不在 map 中。
    /// CLI 用它跳过未变化源的重复解析（capture 后先比指纹，相同则不再
    /// parse，直接按 no-op 处理）。
    pub fn source_fingerprints(
        &self,
        paths: &[String],
    ) -> PortResult<BTreeMap<String, SourceFingerprint>> {
        let conn = self.conn.borrow();
        let mut out = BTreeMap::new();
        for path in paths {
            let row: Option<SourceFingerprint> = conn
                .query_row(
                    "SELECT len_bytes, fingerprint FROM source_scans WHERE source_path = ?1",
                    [path],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()
                .map_err(backend)?;
            if let Some(row) = row {
                out.insert(path.clone(), row);
            }
        }
        Ok(out)
    }

    /// 读取一批源路径已提交的 message 实体数（membership 中 msg_v1_ 行数）。
    ///
    /// CLI 在指纹缓存命中、跳过 parse 时用它上报 unchanged 消息数，保持
    /// `unchanged` 与 `emitted` 同单位（消息数）。
    pub fn source_message_counts(&self, paths: &[String]) -> PortResult<BTreeMap<String, usize>> {
        let conn = self.conn.borrow();
        let mut out = BTreeMap::new();
        for path in paths {
            let count: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM source_membership
                     WHERE source_path = ?1 AND message_id LIKE 'msg_v1_%'",
                    [path],
                    |row| row.get(0),
                )
                .map_err(backend)?;
            out.insert(path.clone(), count as usize);
        }
        Ok(out)
    }

    /// 列出某 provider 在 `source_scans` 中已记录的全部源路径（按路径升序）。
    ///
    /// `sync --discover` 用它做"prior-path diff"：先取该 provider 的已存路径，
    /// 与本次发现的路径比对——存在于已存但本次未出现在磁盘上的，说明源已被删除，
    /// 合成空批（`relation_complete = true`）即可触发 tombstone（R2）。
    ///
    /// `provider_id IS NULL` 的旧行（v8 前或未走 discover 的显式 sync）不会被
    /// 返回——它们对 discover 不可见，不会被误 tombstone（安全保守）。
    pub fn source_paths_for_provider(&self, provider_id: &str) -> PortResult<Vec<String>> {
        let conn = self.conn.borrow();
        let mut stmt = conn
            .prepare(
                "SELECT source_path FROM source_scans
                 WHERE provider_id = ?1
                 ORDER BY source_path ASC",
            )
            .map_err(backend)?;
        let rows = stmt
            .query_map([provider_id], |row| row.get::<_, String>(0))
            .map_err(backend)?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row.map_err(backend)?);
        }
        Ok(out)
    }

    /// Associate previously explicit-synced sources with providers resolved by
    /// canonical-root discovery. Existing associations are immutable.
    pub fn backfill_source_provider_ids(&self, sources: &[(String, String)]) -> PortResult<usize> {
        let mut conn = self.conn.borrow_mut();
        let tx = conn.transaction().map_err(backend)?;
        let changed = {
            let mut stmt = tx
                .prepare(
                    "UPDATE source_scans
                     SET provider_id = ?2
                     WHERE source_path = ?1 AND provider_id IS NULL",
                )
                .map_err(backend)?;
            let mut changed = 0usize;
            for (source_path, provider_id) in sources {
                changed += stmt.execute([source_path, provider_id]).map_err(backend)?;
            }
            changed
        };
        tx.commit().map_err(backend)?;
        Ok(changed)
    }

    /// 列出指定路径中缺少完整 relation marker 的源。
    ///
    /// `sync --discover` 在部分 root scan 后再次遇到同一字节源时，必须重新
    /// stage 它来恢复 `relation_complete`；否则普通 fingerprint skip 会让缺失
    /// marker 永远无法回填。
    pub fn source_paths_requiring_relation_scan(
        &self,
        paths: &[String],
    ) -> PortResult<BTreeSet<String>> {
        let conn = self.conn.borrow();
        let mut out = BTreeSet::new();
        for path in paths {
            let missing: bool = conn
                .query_row(
                    "SELECT EXISTS(
                         SELECT 1 FROM source_scans ss
                         WHERE ss.source_path = ?1
                           AND NOT EXISTS(
                               SELECT 1 FROM source_relation_scans rs
                               WHERE rs.source_path = ss.source_path
                           )
                     )",
                    [path],
                    |row| row.get(0),
                )
                .map_err(backend)?;
            if missing {
                out.insert(path.clone());
            }
        }
        Ok(out)
    }

    fn stable_id_from_store(conn: &Connection, wire: &str) -> PortResult<StableId> {
        let id_json: Option<String> = conn
            .query_row(
                "SELECT id_json FROM fts_ids WHERE wire_id = ?1",
                [wire],
                |row| row.get(0),
            )
            .optional()
            .map_err(backend)?;
        let id = match id_json {
            Some(json) => serde_json::from_str::<StableId>(&json).map_err(backend)?,
            None => StableId::from_wire(wire).ok_or_else(|| {
                PortError::Backend("catalog contains an invalid entity id".into())
            })?,
        };
        if id.as_str() != wire {
            return Err(PortError::Backend(
                "stored identity sidecar does not match its catalog key".into(),
            ));
        }
        Ok(id)
    }

    /// 批量加载场景下的身份解析：优先用已加载的 fts_ids 映射，缺失回退
    /// `from_wire`（与 `stable_id_from_store` 语义一致，避免逐条查询）。
    fn stable_id_from_wire(
        wire: &str,
        id_json_by_wire: &BTreeMap<String, String>,
    ) -> PortResult<StableId> {
        let id = match id_json_by_wire.get(wire) {
            Some(json) => serde_json::from_str::<StableId>(json).map_err(backend)?,
            None => StableId::from_wire(wire).ok_or_else(|| {
                PortError::Backend("catalog contains an invalid entity id".into())
            })?,
        };
        if id.as_str() != wire {
            return Err(PortError::Backend(
                "stored identity sidecar does not match its catalog key".into(),
            ));
        }
        Ok(id)
    }

    fn ensure_stored_identity_metadata_matches(
        &self,
        entries: &[(StableId, Vec<u8>, String)],
    ) -> PortResult<()> {
        let conn = self.conn.borrow();
        // prepare 提升到循环外：200K 实体 × 每次 prepare/finalize 的常数因子
        // 在批量提交里会被放大（见 commit_index_batch_with_relations 的同类 hoist）。
        let mut stmt = conn
            .prepare("SELECT id_json FROM fts_ids WHERE wire_id = ?1")
            .map_err(backend)?;
        for (id, _, _) in entries {
            let id_json: Option<String> = stmt
                .query_row([id.as_str()], |row| row.get(0))
                .optional()
                .map_err(backend)?;
            let Some(id_json) = id_json else {
                continue;
            };
            let stored_id: StableId = serde_json::from_str(&id_json)
                .map_err(|_| PortError::Backend("stored identity sidecar is not valid".into()))?;
            if &stored_id != id {
                return Err(PortError::Backend(
                    "entity has conflicting identity metadata with stored catalog".into(),
                ));
            }
        }
        Ok(())
    }

    fn relation_sources_for_session(
        conn: &Connection,
        session_id: &str,
    ) -> PortResult<BTreeSet<String>> {
        let mut stmt = conn
            .prepare(
                "SELECT source_path FROM source_membership WHERE message_id = ?1
                 UNION
                 SELECT claims.source_path
                 FROM source_placement_membership AS claims
                 JOIN message_placements AS placements
                   ON placements.placement_id = claims.placement_id
                 WHERE placements.session_id = ?1",
            )
            .map_err(backend)?;
        let rows = stmt
            .query_map([session_id], |row| row.get::<_, String>(0))
            .map_err(backend)?;
        let mut sources = BTreeSet::new();
        for row in rows {
            sources.insert(row.map_err(backend)?);
        }
        Ok(sources)
    }

    fn relation_sources_for_message(
        conn: &Connection,
        message_id: &str,
    ) -> PortResult<BTreeSet<String>> {
        let mut stmt = conn
            .prepare(
                "SELECT source_path FROM source_membership WHERE message_id = ?1
                 UNION
                 SELECT claims.source_path
                 FROM source_placement_membership AS claims
                 JOIN message_placements AS placements
                   ON placements.placement_id = claims.placement_id
                 WHERE placements.message_id = ?1",
            )
            .map_err(backend)?;
        let rows = stmt
            .query_map([message_id], |row| row.get::<_, String>(0))
            .map_err(backend)?;
        let mut sources = BTreeSet::new();
        for row in rows {
            sources.insert(row.map_err(backend)?);
        }
        Ok(sources)
    }

    fn require_relation_complete_sources(
        conn: &Connection,
        sources: &BTreeSet<String>,
        require_known_source: bool,
        subject: &str,
    ) -> PortResult<()> {
        if require_known_source && sources.is_empty() {
            return Err(PortError::SchemaIncompatible(format!(
                "{subject} contextual relations are unavailable; re-ingest required"
            )));
        }
        for source_path in sources {
            let complete: bool = conn
                .query_row(
                    "SELECT EXISTS(
                         SELECT 1 FROM source_relation_scans WHERE source_path = ?1
                     )",
                    [source_path],
                    |row| row.get(0),
                )
                .map_err(backend)?;
            if !complete {
                return Err(PortError::SchemaIncompatible(format!(
                    "{subject} contextual relations are incomplete; re-ingest required"
                )));
            }
        }
        Ok(())
    }

    /// 以 durable outbox 包裹一批 upsert，再原子提交 catalog + FTS + generation。
    ///
    /// 阶段一先持久化 intent；阶段二在单个 SQLite 事务中应用所有实体并激活目标
    /// generation。任一实体失败都会回滚整批数据；若进程在两阶段之间终止，下一次
    /// 写打开会把无副作用的 `building` intent 标记为 `aborted`。
    pub fn commit_batch(&self, entries: &[(StableId, Vec<u8>, String)]) -> PortResult<()> {
        self.commit_batch_if_changed(entries).map(|_| ())
    }

    /// Durable batch commit that reports whether a new generation was activated.
    ///
    /// `false` means every catalog payload and indexed text already matched the batch;
    /// no outbox row or generation was created.
    pub fn commit_batch_if_changed(
        &self,
        entries: &[(StableId, Vec<u8>, String)],
    ) -> PortResult<bool> {
        if entries.is_empty() {
            return Ok(false);
        }
        // Validate the complete change set before the no-op shortcut; duplicate IDs must
        // never be silently accepted just because the first copy is already current.
        batch_manifest(entries, &[], &RelationManifests::default())?;
        self.ensure_stored_identity_metadata_matches(entries)?;
        if self.batch_is_current(entries)? {
            return Ok(false);
        }
        let pending = self.begin_index_batch(entries, &[])?;
        self.commit_index_batch(&pending, entries, &[])?;
        Ok(true)
    }

    fn batch_is_current(&self, entries: &[(StableId, Vec<u8>, String)]) -> PortResult<bool> {
        self.batch_is_current_with_derived_context(entries, false)
    }

    fn batch_is_current_with_derived_context(
        &self,
        entries: &[(StableId, Vec<u8>, String)],
        contextual_payloads_are_derived: bool,
    ) -> PortResult<bool> {
        let conn = self.conn.borrow();
        for (id, payload, text) in entries {
            let catalog_payload: Option<Vec<u8>> = conn
                .query_row(
                    "SELECT payload FROM catalog WHERE id = ?1",
                    [id.as_str()],
                    |row| row.get(0),
                )
                .optional()
                .map_err(backend)?;
            let Some(catalog_payload) = catalog_payload else {
                return Ok(false);
            };
            let payload_is_current = if contextual_payloads_are_derived
                && matches!(id.kind(), IdKind::Message | IdKind::Session)
            {
                if catalog_payload.as_slice() == payload.as_slice() {
                    true
                } else {
                    // 存储 payload 可能携带从 v7 关系再生的上下文别名（parent/
                    // is_sidechain/session/spans 等），与传入的合并结果未必逐字节
                    // 一致；因此用与提交路径相同的合并操作判定：把传入 payload 并入
                    // 存储值，若能还原出存储字节才是内容级 no-op。只查存在性会把
                    // merge 实际会应用的 payload-only 变更静默丢弃（如消息新增一个
                    // session 引用而 text 未变）。字节相同则直接短路——与提交路径
                    // “stored == payload 时不做 merge”的行为一致（非 JSON 的旧式
                    // 裸文本行在此保持 no-op 而非误报）。
                    let merged = match id.kind() {
                        IdKind::Message => {
                            merge_message_payloads(id.as_str(), &catalog_payload, payload)?
                        }
                        IdKind::Session => {
                            merge_session_payloads(id.as_str(), &catalog_payload, payload)?
                        }
                        _ => unreachable!(),
                    };
                    merged == catalog_payload
                }
            } else {
                catalog_payload.as_slice() == payload.as_slice()
            };
            if !payload_is_current {
                return Ok(false);
            }
            let id_json: Option<String> = conn
                .query_row(
                    "SELECT id_json FROM fts_ids WHERE wire_id = ?1",
                    [id.as_str()],
                    |row| row.get(0),
                )
                .optional()
                .map_err(backend)?;
            let Some(id_json) = id_json else {
                return Ok(false);
            };
            let stored_id: StableId = serde_json::from_str(&id_json)
                .map_err(|_| PortError::Backend("stored identity sidecar is not valid".into()))?;
            if &stored_id != id {
                return Ok(false);
            }
            // 非 Message 实体不进 fts 全文表（见 commit_index_batch_with_relations），
            // 其"内容一致"只看 catalog payload 与 fts_ids 身份边车。
            if id.kind() != IdKind::Message {
                continue;
            }
            // fts 的 `id` 是内容列（UNINDEXED），按它比较会让每条消息的 current
            // 判定整表扫描（B1 路径 O(N²)）；改经 fts_ids 边车的 fts_rowid 按
            // rowid O(1) 定位。边车缺行或 fts_rowid 为 NULL 时按“无 fts 行”处理
            // （rowid = NULL 匹配不到行）→ 不 current，提交路径会重建该行。
            let indexed_text: Option<String> = conn
                .query_row(
                    "SELECT text FROM fts
                     WHERE rowid = (SELECT fts_rowid FROM fts_ids WHERE wire_id = ?1)",
                    [id.as_str()],
                    |row| row.get(0),
                )
                .optional()
                .map_err(backend)?;
            // fts 存的是 bigram 变换后的正文（见 fts 写入侧），current 判定
            // 必须对同一 text 施加同一 transform 再比较，否则已同步的源每次
            // 重同步都被误判为 not-current、反复推进 generation。
            let expected = bigram_cjk(text);
            if indexed_text.as_deref() != Some(expected.as_str()) {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Commit source-owned entity and relation facts, reporting generation change.
    ///
    /// Complete relation scans replace both entity and placement claims and may
    /// derive tombstones. Incomplete scans union observed claims, derive no
    /// tombstones, and clear the source relation-completeness marker.
    pub fn commit_source_batches_if_changed(&self, sources: &[SourceBatch]) -> PortResult<bool> {
        let mut ordered_sources: Vec<&SourceBatch> = sources.iter().collect();
        ordered_sources.sort_by(|left, right| left.source_path.cmp(&right.source_path));
        let paths: Vec<&str> = ordered_sources
            .iter()
            .map(|source| source.source_path.as_str())
            .collect();
        if paths.windows(2).any(|window| window[0] == window[1]) {
            return Err(PortError::Backend(
                "source batch contains duplicate source paths".into(),
            ));
        }

        // Cheap no-op check FIRST: building the merged view, claimer graph,
        // and manifest below costs O(whole catalog). When every source in
        // this batch is already current (entries, relations, membership,
        // claims, scans), skip all of it and report no generation change.
        // The per-batch cost is then proportional to the batch, not the
        // catalog — this is what makes an unchanged re-sync fast.
        if self.sources_are_current(&ordered_sources)? {
            return Ok(false);
        }

        let scanned_paths: BTreeSet<String> = paths.into_iter().map(str::to_string).collect();
        let current_entities_by_source = self.source_entity_membership_state()?;
        let current_placements_by_source = self.source_placement_membership_state()?;
        let current_activities_by_source = self.source_activity_membership_state()?;
        let stored_placements = self.stored_placements()?;
        let stored_edges = self.stored_edges()?;
        let stored_activities = self.stored_activities()?;

        let mut merged = BTreeMap::<String, (StableId, Vec<u8>, String)>::new();
        let mut observed_placements = BTreeMap::<String, MessagePlacement>::new();
        let mut observed_edges = BTreeMap::<String, MessageEdge>::new();
        let mut observed_activities = BTreeMap::<String, StoredActivity>::new();
        let mut prepared_sources = BTreeMap::<String, PreparedSource>::new();

        for source in ordered_sources {
            let present: BTreeSet<&str> = source
                .entries
                .iter()
                .map(|(id, _, _)| id.as_str())
                .collect();
            if present.len() != source.entries.len() {
                return Err(PortError::Backend(
                    "source batch contains duplicate message ids".into(),
                ));
            }

            let document_id = source
                .entries
                .iter()
                .find(|(id, _, _)| id.kind() == IdKind::Document)
                .map(|(id, _, _)| id.as_str().to_string());
            let incoming_entities: BTreeMap<String, Option<String>> = source
                .entries
                .iter()
                .map(|(id, _, _)| (id.as_str().to_string(), document_id.clone()))
                .collect();
            let prior_entity_memberships = current_entities_by_source
                .get(&source.source_path)
                .cloned()
                .unwrap_or_default();
            let mut final_entities = if source.relation_complete {
                BTreeMap::new()
            } else {
                prior_entity_memberships.clone()
            };
            final_entities.extend(incoming_entities);

            let mut source_placements = BTreeMap::new();
            let mut placement_slots = BTreeSet::new();
            for placement in &source.placements {
                validate_placement(placement)?;
                let placement_id = placement.id.as_str().to_string();
                if source_placements
                    .insert(placement_id.clone(), placement.clone())
                    .is_some()
                {
                    return Err(PortError::Backend(
                        "source batch contains duplicate placement ids".into(),
                    ));
                }
                let slot = (
                    placement.session_id.as_str().to_string(),
                    placement.source_document_id.as_str().to_string(),
                    placement.source_ordinal,
                );
                if !placement_slots.insert(slot) {
                    return Err(PortError::Backend(
                        "source batch contains duplicate placement ordinals".into(),
                    ));
                }
                if let Some(existing) = observed_placements.get(&placement_id) {
                    if existing != placement {
                        return Err(PortError::Backend(format!(
                            "placement {placement_id} has conflicting projections across sources"
                        )));
                    }
                } else {
                    observed_placements.insert(placement_id, placement.clone());
                }
            }

            let mut source_edges = BTreeMap::new();
            for edge in &source.edges {
                validate_edge(edge)?;
                let placement_id = edge.child_placement_id.as_str().to_string();
                if !source_placements.contains_key(&placement_id) {
                    return Err(PortError::Backend(
                        "source batch edge does not belong to an observed placement".into(),
                    ));
                }
                if source_edges
                    .insert(placement_id.clone(), edge.clone())
                    .is_some()
                {
                    return Err(PortError::Backend(
                        "source batch contains duplicate edge children".into(),
                    ));
                }
                if let Some(existing) = observed_edges.get(&placement_id) {
                    if existing != edge {
                        return Err(PortError::Backend(format!(
                            "edge {placement_id} has conflicting projections across sources"
                        )));
                    }
                } else {
                    observed_edges.insert(placement_id, edge.clone());
                }
            }

            let prior_placement_ids = current_placements_by_source
                .get(&source.source_path)
                .cloned()
                .unwrap_or_default();
            let mut final_placement_ids = if source.relation_complete {
                BTreeSet::new()
            } else {
                prior_placement_ids.clone()
            };
            final_placement_ids.extend(source_placements.keys().cloned());

            // 工具活动（v12）：派生活动 id、校验锚点/重复，跨源事实冲突拒绝。
            let mut source_activities = BTreeMap::new();
            for source_activity in &source.activities {
                let stored =
                    stored_activity_from(&source_activity.message_id, &source_activity.activity)?;
                if source_activities
                    .insert(stored.activity_id.clone(), stored.clone())
                    .is_some()
                {
                    return Err(PortError::Backend(format!(
                        "source batch contains duplicate activity ids ({})",
                        stored.activity_id
                    )));
                }
                if let Some(existing) = observed_activities.get(&stored.activity_id) {
                    if existing != &stored {
                        return Err(PortError::Backend(format!(
                            "activity {} has conflicting projections across sources",
                            stored.activity_id
                        )));
                    }
                } else {
                    observed_activities.insert(stored.activity_id.clone(), stored);
                }
            }
            let prior_activity_ids = current_activities_by_source
                .get(&source.source_path)
                .cloned()
                .unwrap_or_default();
            let mut final_activity_ids = if source.relation_complete {
                BTreeSet::new()
            } else {
                prior_activity_ids.clone()
            };
            final_activity_ids.extend(source_activities.keys().cloned());

            let replacement = SourceReplacementManifest {
                source_path: source.source_path.clone(),
                entity_memberships: final_entities
                    .into_iter()
                    .map(|(entity_id, document_id)| SourceEntityMembershipManifest {
                        entity_id,
                        document_id,
                    })
                    .collect(),
                placement_ids: final_placement_ids
                    .iter()
                    .map(|wire| {
                        PlacementId::from_wire(wire).ok_or_else(|| {
                            PortError::Backend(format!("invalid placement claim id: {wire}"))
                        })
                    })
                    .collect::<PortResult<Vec<_>>>()?,
                activity_ids: final_activity_ids.into_iter().collect(),
                relation_complete: source.relation_complete,
                len_bytes: source.len_bytes,
                fingerprint: source.fingerprint.clone(),
                provider_id: source.provider_id.clone(),
                resume_claim: source.resume_claim.clone(),
            };
            prepared_sources.insert(
                source.source_path.clone(),
                PreparedSource {
                    relation_complete: source.relation_complete,
                    prior_entity_memberships,
                    prior_placement_ids,
                    prior_activity_ids,
                    observed_placements: source_placements,
                    observed_edges: source_edges,
                    replacement,
                },
            );

            for (id, payload, text) in &source.entries {
                if let Some((old_id, old_payload, old_text)) = merged.get(id.as_str()) {
                    if old_id != id {
                        return Err(PortError::Backend(
                            "entity has conflicting identity metadata across sources".into(),
                        ));
                    }
                    if old_payload != payload || old_text != text {
                        let union = match id.kind() {
                            IdKind::Session => {
                                merge_session_payloads(id.as_str(), old_payload, payload)?
                            }
                            IdKind::Message => {
                                merge_message_payloads(id.as_str(), old_payload, payload)?
                            }
                            _ => {
                                return Err(PortError::Backend(
                                    "entity has conflicting projections across sources".into(),
                                ));
                            }
                        };
                        // 合并后的 payload 是内容的权威投影：FTS 正文必须从它重投影
                        // （与 rebuild_index 同一投影函数），而不是取“排序最后处理的
                        // 源的原始 text”——后者在 text 较短源排最后时会与 payload 分叉
                        // （长文本在 payload 但搜不到，需 rebuild 才恢复），也会让按源
                        // 分批 sync 时 generation 反复推进、内容级 no-op 失效。
                        let merged_text = if id.kind() == IdKind::Message {
                            searchable_text(&union)
                        } else {
                            text.clone()
                        };
                        merged.insert(id.as_str().to_string(), (id.clone(), union, merged_text));
                        continue;
                    }
                } else {
                    merged.insert(
                        id.as_str().to_string(),
                        (id.clone(), payload.clone(), text.clone()),
                    );
                }
            }
        }

        // 合并前先批量读取 catalog 中已有的 payload(分块 IN,同 get_many 模式),
        // 取代逐实体 get 的 N+1;与 get 语义一致:目录中不存在的 id 视为 None。
        let merged_ids: Vec<StableId> = merged.values().map(|(id, _, _)| id.clone()).collect();
        let stored_payloads = self.get_many(&merged_ids)?;
        let stored_by_id: BTreeMap<String, Vec<u8>> = stored_payloads
            .into_iter()
            .filter_map(|(id, payload)| payload.map(|payload| (id.as_str().to_string(), payload)))
            .collect();

        for (id, payload, text) in merged.values_mut() {
            let Some(stored) = stored_by_id.get(id.as_str()) else {
                continue;
            };
            if stored == payload {
                continue;
            }
            match id.kind() {
                IdKind::Session => {
                    *payload = merge_session_payloads(id.as_str(), stored, payload)?;
                }
                IdKind::Message => {
                    let union = merge_message_payloads(id.as_str(), stored, payload)?;
                    // 与 stored 合并后再次重投影正文：合并结果可能以 stored 中更长的
                    // text 为准，FTS 必须索引 searchable_text(合并后 payload) 而非
                    // 来源侧原始 text，否则 payload 与搜索索引再次分叉。
                    *text = searchable_text(&union);
                    *payload = union;
                }
                _ => continue,
            };
        }

        let mut final_entity_claimers = BTreeMap::<String, BTreeSet<String>>::new();
        for (source_path, memberships) in &current_entities_by_source {
            if scanned_paths.contains(source_path) {
                continue;
            }
            for entity_id in memberships.keys() {
                final_entity_claimers
                    .entry(entity_id.clone())
                    .or_default()
                    .insert(source_path.clone());
            }
        }
        let mut final_placement_claimers = BTreeMap::<String, BTreeSet<String>>::new();
        for (source_path, placement_ids) in &current_placements_by_source {
            if scanned_paths.contains(source_path) {
                continue;
            }
            for placement_id in placement_ids {
                final_placement_claimers
                    .entry(placement_id.clone())
                    .or_default()
                    .insert(source_path.clone());
            }
        }
        for (source_path, prepared) in &prepared_sources {
            for membership in &prepared.replacement.entity_memberships {
                final_entity_claimers
                    .entry(membership.entity_id.clone())
                    .or_default()
                    .insert(source_path.clone());
            }
            for placement_id in &prepared.replacement.placement_ids {
                final_placement_claimers
                    .entry(placement_id.as_str().to_string())
                    .or_default()
                    .insert(source_path.clone());
            }
        }
        let mut final_activity_claimers = BTreeMap::<String, BTreeSet<String>>::new();
        for (source_path, activity_ids) in &current_activities_by_source {
            if scanned_paths.contains(source_path) {
                continue;
            }
            for activity_id in activity_ids {
                final_activity_claimers
                    .entry(activity_id.clone())
                    .or_default()
                    .insert(source_path.clone());
            }
        }
        for (source_path, prepared) in &prepared_sources {
            for activity_id in &prepared.replacement.activity_ids {
                final_activity_claimers
                    .entry(activity_id.clone())
                    .or_default()
                    .insert(source_path.clone());
            }
        }

        let mut deletes = BTreeMap::new();
        let mut placement_delete_ids = BTreeSet::new();
        let mut activity_delete_ids = BTreeSet::new();
        // 失败/不完整扫描不变量（与 fast-resume `failed_incremental_scan` 同一
        // 原则：任何 IO/解析/目录错误都不删除已索引内容）：relation_complete=false
        // 的源绝不推导 tombstone——"这次没看到"不是"已被删除"，只有完整成功的
        // 扫描才能确认缺席。CLI 层对截断尾源（Invalid 健康度）直接 retain 旧索引
        // （不提交批次），同样不会走到这里。
        for prepared in prepared_sources.values() {
            if !prepared.relation_complete {
                continue;
            }
            let final_entity_ids: BTreeSet<&str> = prepared
                .replacement
                .entity_memberships
                .iter()
                .map(|membership| membership.entity_id.as_str())
                .collect();
            for prior in prepared.prior_entity_memberships.keys() {
                if !final_entity_ids.contains(prior.as_str())
                    && !final_entity_claimers.contains_key(prior)
                {
                    let id = StableId::from_wire(prior).ok_or_else(|| {
                        PortError::Backend(format!("invalid membership id: {prior}"))
                    })?;
                    deletes.insert(prior.clone(), id);
                }
            }

            let final_placement_ids: BTreeSet<&str> = prepared
                .replacement
                .placement_ids
                .iter()
                .map(PlacementId::as_str)
                .collect();
            for prior in &prepared.prior_placement_ids {
                if !final_placement_ids.contains(prior.as_str())
                    && !final_placement_claimers.contains_key(prior)
                    && stored_placements.contains_key(prior)
                {
                    placement_delete_ids.insert(prior.clone());
                }
            }

            let final_activity_ids: BTreeSet<&str> = prepared
                .replacement
                .activity_ids
                .iter()
                .map(String::as_str)
                .collect();
            for prior in &prepared.prior_activity_ids {
                if !final_activity_ids.contains(prior.as_str())
                    && !final_activity_claimers.contains_key(prior)
                    && stored_activities.contains_key(prior)
                {
                    activity_delete_ids.insert(prior.clone());
                }
            }
        }

        for (placement_id, placement) in &observed_placements {
            let Some(stored) = stored_placements.get(placement_id) else {
                continue;
            };
            if stored.matches(placement) {
                continue;
            }
            let claimers = final_placement_claimers
                .get(placement_id)
                .cloned()
                .unwrap_or_default();
            let all_claimers_observed_same_placement = !claimers.is_empty()
                && claimers.iter().all(|source_path| {
                    prepared_sources.get(source_path).is_some_and(|prepared| {
                        prepared.observed_placements.get(placement_id) == Some(placement)
                    })
                });
            if !all_claimers_observed_same_placement {
                return Err(PortError::Backend(format!(
                    "placement {placement_id} conflicts with a source that did not observe the same placement"
                )));
            }
        }

        for (placement_id, edge) in &observed_edges {
            let current_matches = stored_edges
                .get(placement_id)
                .is_some_and(|stored| stored.matches(edge));
            let claimers = final_placement_claimers
                .get(placement_id)
                .cloned()
                .unwrap_or_default();
            if !current_matches {
                let all_claimers_observed_same_edge = !claimers.is_empty()
                    && claimers.iter().all(|source_path| {
                        prepared_sources.get(source_path).is_some_and(|prepared| {
                            prepared.observed_edges.get(placement_id) == Some(edge)
                        })
                    });
                if !all_claimers_observed_same_edge {
                    return Err(PortError::Backend(format!(
                        "edge {placement_id} conflicts with a source that did not observe the same edge"
                    )));
                }
            }
        }

        let mut edge_delete_ids: BTreeSet<String> = placement_delete_ids
            .iter()
            .filter(|placement_id| stored_edges.contains_key(*placement_id))
            .cloned()
            .collect();
        for prepared in prepared_sources.values() {
            for placement_id in prepared.observed_placements.keys() {
                if prepared.observed_edges.contains_key(placement_id)
                    || !stored_edges.contains_key(placement_id)
                {
                    continue;
                }
                if observed_edges.contains_key(placement_id) {
                    return Err(PortError::Backend(format!(
                        "edge {placement_id} has inconsistent complete-source claims"
                    )));
                }
                let claimers = final_placement_claimers
                    .get(placement_id)
                    .cloned()
                    .unwrap_or_default();
                let all_claimers_observed_root = !claimers.is_empty()
                    && claimers.iter().all(|source_path| {
                        prepared_sources.get(source_path).is_some_and(|claimer| {
                            claimer.observed_placements.contains_key(placement_id)
                                && !claimer.observed_edges.contains_key(placement_id)
                        })
                    });
                if !all_claimers_observed_root {
                    return Err(PortError::Backend(format!(
                        "edge {placement_id} conflicts with a source that did not observe the same root"
                    )));
                }
                edge_delete_ids.insert(placement_id.clone());
            }
        }

        let upserts: Vec<(StableId, Vec<u8>, String)> = merged.into_values().collect();
        let deletes: Vec<StableId> = deletes.into_values().collect();
        let relations = RelationManifests {
            relation_upserts: observed_placements
                .into_values()
                .map(RelationUpsertManifest::Placement)
                .chain(
                    observed_edges
                        .into_values()
                        .map(RelationUpsertManifest::Edge),
                )
                .chain(
                    observed_activities
                        .into_values()
                        .map(RelationUpsertManifest::Activity),
                )
                .collect(),
            relation_deletes: edge_delete_ids
                .into_iter()
                .map(|wire| {
                    PlacementId::from_wire(&wire)
                        .map(RelationDeleteManifest::Edge)
                        .ok_or_else(|| {
                            PortError::Backend(format!("invalid edge tombstone id: {wire}"))
                        })
                })
                .chain(placement_delete_ids.into_iter().map(|wire| {
                    PlacementId::from_wire(&wire)
                        .map(RelationDeleteManifest::Placement)
                        .ok_or_else(|| {
                            PortError::Backend(format!("invalid placement tombstone id: {wire}"))
                        })
                }))
                .chain(
                    activity_delete_ids
                        .into_iter()
                        .map(|id| Ok(RelationDeleteManifest::Activity(id))),
                )
                .collect::<PortResult<Vec<_>>>()?,
            source_replacements: prepared_sources
                .into_values()
                .map(|prepared| prepared.replacement)
                .collect(),
        };

        batch_manifest(&upserts, &deletes, &relations)?;
        self.ensure_stored_identity_metadata_matches(&upserts)?;
        if self.source_batches_are_current(&upserts, &relations)? {
            return Ok(false);
        }

        let pending = self.begin_index_batch_with_relations(&upserts, &deletes, &relations)?;
        self.commit_index_batch_with_relations(&pending, &upserts, &deletes, &relations)?;
        Ok(true)
    }

    /// True when every source in the batch is already fully current: catalog
    /// entries (payload + fts text), placements, edges, entity membership,
    /// placement claims, scan record, and relation-completeness marker all
    /// match the stored state. Called before any heavy merge/manifest work
    /// so an unchanged re-sync costs O(batch), not O(whole catalog). Every
    /// query is scoped to this batch's sources/ids — no full-table loads.
    fn sources_are_current(&self, ordered_sources: &[&SourceBatch]) -> PortResult<bool> {
        let conn = self.conn.borrow();
        for source in ordered_sources {
            // A source that has never been scanned cannot be current; skip the
            // per-entity queries (which dominate on first ingest of an
            // empty catalog) and go straight to the heavy path.
            let stored_scan: Option<(Option<i64>, Option<String>, Option<String>)> = conn
                .query_row(
                    "SELECT len_bytes, fingerprint, provider_id
                     FROM source_scans WHERE source_path = ?1",
                    [&source.source_path],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .optional()
                .map_err(backend)?;
            let Some((stored_len, stored_fingerprint, stored_provider_id)) = stored_scan else {
                return Ok(false);
            };
            // 指纹缓存参与 current 判定：len/fingerprint 任一变说明源字节已变而
            // 缓存未更新，必须重解析并重写缓存。只查扫描行存在会让缓存永不收敛，
            // CLI 每次运行都重解析全部源。
            if source.len_bytes != stored_len
                || source.fingerprint.as_deref() != stored_fingerprint.as_deref()
            {
                return Ok(false);
            }
            // provider_id 回填同样参与 current 判定：discover 发现的源可能携带
            // provider_id，而已存行为 NULL（先显式 sync 后 discovery 的场景）。
            // 仅当 incoming 是 Some 且与 stored 不同时才判 not-current——
            // incoming None（显式 sync）不覆盖已有 provider_id，保持一致。
            if let Some(incoming_provider_id) = source.provider_id.as_deref()
                && stored_provider_id.as_deref() != Some(incoming_provider_id)
            {
                return Ok(false);
            }

            // Catalog entries: batched payload reads, chunked under the
            // SQLite variable limit.
            let ids: Vec<&str> = source
                .entries
                .iter()
                .map(|(id, _, _)| id.as_str())
                .collect();
            let mut payloads: BTreeMap<String, Vec<u8>> = BTreeMap::new();
            for chunk in chunk_ids(&ids) {
                let placeholders = chunk.iter().map(|_| "?").collect::<Vec<_>>().join(",");
                let mut stmt = conn
                    .prepare(&format!(
                        "SELECT id, payload FROM catalog WHERE id IN ({placeholders})"
                    ))
                    .map_err(backend)?;
                let rows = stmt
                    .query_map(rusqlite::params_from_iter(chunk.iter().copied()), |row| {
                        Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?))
                    })
                    .map_err(backend)?;
                for row in rows {
                    let (id, payload) = row.map_err(backend)?;
                    payloads.insert(id, payload);
                }
            }
            for (id, payload, _text) in &source.entries {
                if payloads.get(id.as_str()).map(Vec::as_slice) != Some(payload.as_slice()) {
                    return Ok(false);
                }
            }
            // Indexed text: batched reads mapping wire_id -> fts text.
            let mut fts_text: BTreeMap<String, String> = BTreeMap::new();
            for chunk in chunk_ids(&ids) {
                let placeholders = chunk.iter().map(|_| "?").collect::<Vec<_>>().join(",");
                let mut stmt = conn
                    .prepare(&format!(
                        "SELECT fi.wire_id, f.text FROM fts f
                         JOIN fts_ids fi ON fi.id_json = f.id
                         WHERE fi.wire_id IN ({placeholders})"
                    ))
                    .map_err(backend)?;
                let rows = stmt
                    .query_map(rusqlite::params_from_iter(chunk.iter().copied()), |row| {
                        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                    })
                    .map_err(backend)?;
                for row in rows {
                    let (wire_id, text) = row.map_err(backend)?;
                    fts_text.insert(wire_id, text);
                }
            }
            for (id, _payload, text) in &source.entries {
                // 与写入侧同一 transform：fts 正文存的是 bigram(text)。
                let expected = bigram_cjk(text);
                if fts_text.get(id.as_str()).map(String::as_str) != Some(expected.as_str()) {
                    return Ok(false);
                }
            }
            // Entity membership for this source only.
            let mut stmt = conn
                .prepare(
                    "SELECT message_id, document_id FROM source_membership
                     WHERE source_path = ?1 ORDER BY message_id",
                )
                .map_err(backend)?;
            let rows = stmt
                .query_map([&source.source_path], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?))
                })
                .map_err(backend)?;
            let mut stored_membership = BTreeMap::new();
            for row in rows {
                let (entity_id, document_id) = row.map_err(backend)?;
                stored_membership.insert(entity_id, document_id);
            }
            let document_id = source
                .entries
                .iter()
                .find(|(id, _, _)| id.kind() == IdKind::Document)
                .map(|(id, _, _)| id.as_str().to_string());
            let incoming_entities: BTreeMap<String, Option<String>> = source
                .entries
                .iter()
                .map(|(id, _, _)| (id.as_str().to_string(), document_id.clone()))
                .collect();
            if stored_membership != incoming_entities {
                return Ok(false);
            }
            // Placement claims for this source only.
            let mut stmt = conn
                .prepare(
                    "SELECT placement_id FROM source_placement_membership
                     WHERE source_path = ?1 ORDER BY placement_id",
                )
                .map_err(backend)?;
            let rows = stmt
                .query_map([&source.source_path], |row| row.get::<_, String>(0))
                .map_err(backend)?;
            let stored_placements: BTreeSet<String> =
                rows.collect::<Result<_, _>>().map_err(backend)?;
            let expected_placements: BTreeSet<String> = source
                .placements
                .iter()
                .map(|p| p.id.as_str().to_string())
                .collect();
            if stored_placements != expected_placements {
                return Ok(false);
            }
            // Stored placements for this source's ids (batched, chunked).
            let mut stored_placements: BTreeMap<String, StoredPlacement> = BTreeMap::new();
            let pids: Vec<&str> = source.placements.iter().map(|p| p.id.as_str()).collect();
            for chunk in chunk_ids(&pids) {
                let placeholders = chunk.iter().map(|_| "?").collect::<Vec<_>>().join(",");
                let mut stmt = conn
                    .prepare(&format!(
                        "SELECT placement_id, session_id, document_id, message_id,
                                source_ordinal, is_sidechain, byte_start, byte_end
                         FROM message_placements WHERE placement_id IN ({placeholders})"
                    ))
                    .map_err(backend)?;
                let rows = stmt
                    .query_map(rusqlite::params_from_iter(chunk.iter().copied()), |row| {
                        let start: Option<i64> = row.get(6)?;
                        let end: Option<i64> = row.get(7)?;
                        Ok((
                            row.get::<_, String>(0)?,
                            StoredPlacement {
                                session_id: row.get(1)?,
                                document_id: row.get(2)?,
                                message_id: row.get(3)?,
                                source_ordinal: row.get(4)?,
                                is_sidechain: row.get(5)?,
                                span: match (start, end) {
                                    (Some(start), Some(end)) => Some((start as u64, end as u64)),
                                    _ => None,
                                },
                            },
                        ))
                    })
                    .map_err(backend)?;
                for row in rows {
                    let (pid, stored) = row.map_err(backend)?;
                    stored_placements.insert(pid, stored);
                }
            }
            for placement in &source.placements {
                if !stored_placements
                    .get(placement.id.as_str())
                    .is_some_and(|stored| stored.matches(placement))
                {
                    return Ok(false);
                }
            }
            // Stored edges for this source's ids (batched, chunked).
            let mut stored_edges: BTreeMap<String, (String, Option<String>, String)> =
                BTreeMap::new();
            let cids: Vec<&str> = source
                .edges
                .iter()
                .map(|e| e.child_placement_id.as_str())
                .collect();
            for chunk in chunk_ids(&cids) {
                let placeholders = chunk.iter().map(|_| "?").collect::<Vec<_>>().join(",");
                let mut stmt = conn
                    .prepare(&format!(
                        "SELECT child_placement_id, parent_message_id, parent_native_id, relation
                         FROM message_edges WHERE child_placement_id IN ({placeholders})"
                    ))
                    .map_err(backend)?;
                let rows = stmt
                    .query_map(rusqlite::params_from_iter(chunk.iter().copied()), |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            (
                                row.get::<_, String>(1)?,
                                row.get::<_, Option<String>>(2)?,
                                row.get::<_, String>(3)?,
                            ),
                        ))
                    })
                    .map_err(backend)?;
                for row in rows {
                    let (cid, edge) = row.map_err(backend)?;
                    stored_edges.insert(cid, edge);
                }
            }
            for edge in &source.edges {
                let matches = stored_edges
                    .get(edge.child_placement_id.as_str())
                    .is_some_and(|(parent, native, relation)| {
                        parent == edge.parent_message_id.as_str()
                            && native.as_deref() == edge.parent_native_id.as_deref()
                            && relation == edge.relation.as_str()
                    });
                if !matches {
                    return Ok(false);
                }
            }
            // Tool-activity claims for this source only.
            let mut stmt = conn
                .prepare(
                    "SELECT activity_id FROM tool_activity_membership
                     WHERE source_path = ?1 ORDER BY activity_id",
                )
                .map_err(backend)?;
            let rows = stmt
                .query_map([&source.source_path], |row| row.get::<_, String>(0))
                .map_err(backend)?;
            let stored_activity_claims: BTreeSet<String> =
                rows.collect::<Result<_, _>>().map_err(backend)?;
            let expected_activity_claims: BTreeSet<String> = source
                .activities
                .iter()
                .map(|source_activity| {
                    stored_activity_from(&source_activity.message_id, &source_activity.activity)
                        .map(|stored| stored.activity_id)
                })
                .collect::<PortResult<BTreeSet<_>>>()?;
            if stored_activity_claims != expected_activity_claims {
                return Ok(false);
            }
            // Stored activity rows for this source's ids (batched, chunked).
            let mut stored_rows: BTreeMap<String, StoredActivity> = BTreeMap::new();
            let activity_ids: Vec<String> = expected_activity_claims.into_iter().collect();
            for chunk in chunk_ids(&activity_ids) {
                let placeholders = chunk.iter().map(|_| "?").collect::<Vec<_>>().join(",");
                let mut stmt = conn
                    .prepare(&format!(
                        "SELECT activity_id, message_id, kind, actor, name, target, status
                         FROM tool_activities WHERE activity_id IN ({placeholders})"
                    ))
                    .map_err(backend)?;
                let rows = stmt
                    .query_map(rusqlite::params_from_iter(chunk.iter()), |row| {
                        let id: String = row.get(0)?;
                        Ok((
                            id.clone(),
                            StoredActivity {
                                activity_id: id,
                                message_id: row.get(1)?,
                                kind: row.get(2)?,
                                actor: row.get(3)?,
                                name: row.get(4)?,
                                target: row.get(5)?,
                                status: row.get(6)?,
                            },
                        ))
                    })
                    .map_err(backend)?;
                for row in rows {
                    let (id, stored) = row.map_err(backend)?;
                    stored_rows.insert(id, stored);
                }
            }
            for source_activity in &source.activities {
                let expected =
                    stored_activity_from(&source_activity.message_id, &source_activity.activity)?;
                if !stored_rows
                    .get(&expected.activity_id)
                    .is_some_and(|stored| stored.matches(&expected))
                {
                    return Ok(false);
                }
            }
            // Completeness marker (scan record already checked at loop head).
            let complete: bool = conn
                .query_row(
                    "SELECT 1 FROM source_relation_scans WHERE source_path = ?1",
                    [&source.source_path],
                    |_| Ok(()),
                )
                .optional()
                .map_err(backend)?
                .is_some();
            if complete != source.relation_complete {
                return Ok(false);
            }
            // Resume Metadata 声明（ADR-0009）同样参与 no-op 判定：声明变化
            // （含 None↔Some）必须走提交路径原子替换/清除，不能因其余字节
            // 未变而跳过。
            let stored_resume = stored_resume_claim(&conn, &source.source_path)?;
            let expected_resume = source
                .resume_claim
                .as_ref()
                .map(StoredResumeClaim::from_claim);
            if stored_resume != expected_resume {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn source_entity_membership_state(
        &self,
    ) -> PortResult<BTreeMap<String, BTreeMap<String, Option<String>>>> {
        let conn = self.conn.borrow();
        let mut stmt = conn
            .prepare(
                "SELECT source_path, message_id, document_id
                 FROM source_membership ORDER BY source_path, message_id",
            )
            .map_err(backend)?;
        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                ))
            })
            .map_err(backend)?;
        let mut state = BTreeMap::<String, BTreeMap<String, Option<String>>>::new();
        for row in rows {
            let (source_path, entity_id, document_id) = row.map_err(backend)?;
            state
                .entry(source_path)
                .or_default()
                .insert(entity_id, document_id);
        }
        Ok(state)
    }

    #[cfg(test)]
    fn source_message_ids(&self, source_path: &str) -> PortResult<Vec<String>> {
        Ok(self
            .source_entity_membership_state()?
            .remove(source_path)
            .unwrap_or_default()
            .into_keys()
            .collect())
    }

    fn source_placement_membership_state(&self) -> PortResult<BTreeMap<String, BTreeSet<String>>> {
        let conn = self.conn.borrow();
        let mut stmt = conn
            .prepare(
                "SELECT source_path, placement_id
                 FROM source_placement_membership ORDER BY source_path, placement_id",
            )
            .map_err(backend)?;
        let rows = stmt
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(backend)?;
        let mut state = BTreeMap::<String, BTreeSet<String>>::new();
        for row in rows {
            let (source_path, placement_id) = row.map_err(backend)?;
            state.entry(source_path).or_default().insert(placement_id);
        }
        Ok(state)
    }

    fn stored_placements(&self) -> PortResult<BTreeMap<String, StoredPlacement>> {
        let conn = self.conn.borrow();
        Self::stored_placements_from(&conn)
    }

    fn stored_placements_from(conn: &Connection) -> PortResult<BTreeMap<String, StoredPlacement>> {
        let mut stmt = conn
            .prepare(
                "SELECT placement_id, session_id, document_id, message_id,
                        source_ordinal, is_sidechain, byte_start, byte_end
                 FROM message_placements ORDER BY placement_id",
            )
            .map_err(backend)?;
        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, Option<i64>>(6)?,
                    row.get::<_, Option<i64>>(7)?,
                ))
            })
            .map_err(backend)?;
        let mut placements = BTreeMap::new();
        for row in rows {
            let (placement_id, session_id, document_id, message_id, ordinal, sidechain, start, end) =
                row.map_err(backend)?;
            let span = match (start, end) {
                (None, None) => None,
                (Some(start), Some(end)) => Some((
                    u64::try_from(start).map_err(backend)?,
                    u64::try_from(end).map_err(backend)?,
                )),
                _ => {
                    return Err(PortError::Backend(
                        "stored placement has a partial span".into(),
                    ));
                }
            };
            placements.insert(
                placement_id,
                StoredPlacement {
                    session_id,
                    document_id,
                    message_id,
                    source_ordinal: u32::try_from(ordinal).map_err(backend)?,
                    is_sidechain: sidechain != 0,
                    span,
                },
            );
        }
        Ok(placements)
    }

    fn stored_edges(&self) -> PortResult<BTreeMap<String, StoredEdge>> {
        let conn = self.conn.borrow();
        Self::stored_edges_from(&conn)
    }

    fn stored_edges_from(conn: &Connection) -> PortResult<BTreeMap<String, StoredEdge>> {
        let mut stmt = conn
            .prepare(
                "SELECT child_placement_id, parent_message_id, parent_native_id, relation
                 FROM message_edges ORDER BY child_placement_id",
            )
            .map_err(backend)?;
        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    StoredEdge {
                        parent_message_id: row.get(1)?,
                        parent_native_id: row.get(2)?,
                        relation: row.get(3)?,
                    },
                ))
            })
            .map_err(backend)?;
        let mut edges = BTreeMap::new();
        for row in rows {
            let (placement_id, edge) = row.map_err(backend)?;
            edges.insert(placement_id, edge);
        }
        Ok(edges)
    }

    fn stored_activities(&self) -> PortResult<BTreeMap<String, StoredActivity>> {
        let conn = self.conn.borrow();
        Self::stored_activities_from(&conn)
    }

    fn stored_activities_from(conn: &Connection) -> PortResult<BTreeMap<String, StoredActivity>> {
        let mut stmt = conn
            .prepare(
                "SELECT activity_id, message_id, kind, actor, name, target, status
                 FROM tool_activities ORDER BY activity_id",
            )
            .map_err(backend)?;
        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    StoredActivity {
                        activity_id: String::new(), // 键即 id，行内不重复承载
                        message_id: row.get(1)?,
                        kind: row.get(2)?,
                        actor: row.get(3)?,
                        name: row.get(4)?,
                        target: row.get(5)?,
                        status: row.get(6)?,
                    },
                ))
            })
            .map_err(backend)?;
        let mut activities = BTreeMap::new();
        for row in rows {
            let (activity_id, mut activity) = row.map_err(backend)?;
            activity.activity_id = activity_id.clone();
            activities.insert(activity_id, activity);
        }
        Ok(activities)
    }

    fn source_activity_membership_state(&self) -> PortResult<BTreeMap<String, BTreeSet<String>>> {
        let conn = self.conn.borrow();
        let mut stmt = conn
            .prepare(
                "SELECT source_path, activity_id
                 FROM tool_activity_membership ORDER BY source_path, activity_id",
            )
            .map_err(backend)?;
        let rows = stmt
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(backend)?;
        let mut state = BTreeMap::<String, BTreeSet<String>>::new();
        for row in rows {
            let (source_path, activity_id) = row.map_err(backend)?;
            state.entry(source_path).or_default().insert(activity_id);
        }
        Ok(state)
    }

    fn regenerate_compatibility_aliases_in_tx(
        tx: &rusqlite::Transaction<'_>,
        batch_sources: &[String],
    ) -> PortResult<()> {
        let complete_sources = {
            let mut stmt = tx
                .prepare("SELECT source_path FROM source_relation_scans")
                .map_err(backend)?;
            let rows = stmt
                .query_map([], |row| row.get::<_, String>(0))
                .map_err(backend)?;
            let mut sources = BTreeSet::new();
            for row in rows {
                sources.insert(row.map_err(backend)?);
            }
            sources
        };

        let mut claimers_by_entity = BTreeMap::<String, BTreeSet<String>>::new();
        let mut session_document_claims = BTreeMap::<String, BTreeSet<String>>::new();
        {
            let mut stmt = tx
                .prepare(
                    "SELECT source_path, message_id, document_id
                     FROM source_membership",
                )
                .map_err(backend)?;
            let rows = stmt
                .query_map([], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Option<String>>(2)?,
                    ))
                })
                .map_err(backend)?;
            for row in rows {
                let (source_path, entity_id, document_id) = row.map_err(backend)?;
                claimers_by_entity
                    .entry(entity_id.clone())
                    .or_default()
                    .insert(source_path);
                if entity_id.starts_with(IdKind::Session.prefix())
                    && let Some(document_id) = document_id
                {
                    session_document_claims
                        .entry(entity_id)
                        .or_default()
                        .insert(document_id);
                }
            }
        }
        {
            let mut stmt = tx
                .prepare(
                    "SELECT claims.source_path, placements.session_id,
                            placements.document_id, placements.message_id
                     FROM source_placement_membership AS claims
                     JOIN message_placements AS placements
                       ON placements.placement_id = claims.placement_id",
                )
                .map_err(backend)?;
            let rows = stmt
                .query_map([], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                    ))
                })
                .map_err(backend)?;
            for row in rows {
                let (source_path, session_id, document_id, message_id) = row.map_err(backend)?;
                for entity_id in [session_id, document_id, message_id] {
                    claimers_by_entity
                        .entry(entity_id)
                        .or_default()
                        .insert(source_path.clone());
                }
            }
        }

        let fully_complete_entities: BTreeSet<String> = claimers_by_entity
            .into_iter()
            .filter_map(|(entity_id, claimers)| {
                // Only entities whose claimers intersect this batch's sources
                // can have their aliases changed by this commit; regenerating
                // the whole catalog per batch is what made first ingest
                // O(n²). Fully-complete still requires every claimer scanned.
                let touched_by_batch = claimers
                    .iter()
                    .any(|source_path| batch_sources.iter().any(|batch| batch == source_path));
                (!claimers.is_empty()
                    && touched_by_batch
                    && claimers
                        .iter()
                        .all(|source_path| complete_sources.contains(source_path)))
                .then_some(entity_id)
            })
            .collect();
        if fully_complete_entities.is_empty() {
            return Ok(());
        }

        let placements = Self::stored_placements_from(tx)?;
        let edges = Self::stored_edges_from(tx)?;
        let mut placements_by_message = BTreeMap::<String, Vec<(String, StoredPlacement)>>::new();
        let mut placements_by_session = BTreeMap::<String, Vec<(String, StoredPlacement)>>::new();
        for (placement_id, placement) in placements {
            placements_by_message
                .entry(placement.message_id.clone())
                .or_default()
                .push((placement_id.clone(), placement.clone()));
            placements_by_session
                .entry(placement.session_id.clone())
                .or_default()
                .push((placement_id, placement));
        }
        for placements in placements_by_message
            .values_mut()
            .chain(placements_by_session.values_mut())
        {
            placements.sort_by(|left, right| {
                (
                    left.1.document_id.as_str(),
                    left.1.source_ordinal,
                    left.0.as_str(),
                )
                    .cmp(&(
                        right.1.document_id.as_str(),
                        right.1.source_ordinal,
                        right.0.as_str(),
                    ))
            });
        }

        for entity_id in fully_complete_entities {
            let Some(id) = StableId::from_wire(&entity_id) else {
                return Err(PortError::Backend(
                    "source membership contains an invalid entity id".into(),
                ));
            };
            if !matches!(id.kind(), IdKind::Message | IdKind::Session) {
                continue;
            }
            let payload: Option<Vec<u8>> = tx
                .query_row(
                    "SELECT payload FROM catalog WHERE id = ?1",
                    [&entity_id],
                    |row| row.get(0),
                )
                .optional()
                .map_err(backend)?;
            let Some(payload) = payload else {
                continue;
            };
            let mut map = match serde_json::from_slice::<serde_json::Value>(&payload) {
                Ok(serde_json::Value::Object(map)) => map,
                _ => continue,
            };

            match id.kind() {
                IdKind::Message => {
                    let placements = placements_by_message
                        .get(&entity_id)
                        .cloned()
                        .unwrap_or_default();
                    if placements.is_empty() {
                        continue;
                    }
                    let sessions: Vec<String> = placements
                        .iter()
                        .map(|(_, placement)| placement.session_id.clone())
                        .collect::<BTreeSet<_>>()
                        .into_iter()
                        .collect();
                    map.insert(
                        "session".into(),
                        sessions
                            .first()
                            .cloned()
                            .map_or(serde_json::Value::Null, serde_json::Value::String),
                    );
                    map.insert("sessions".into(), serde_json::json!(sessions));

                    let spans: Vec<serde_json::Value> = placements
                        .iter()
                        .filter_map(|(placement_id, placement)| {
                            placement.span.map(|(start, end)| {
                                serde_json::json!({
                                    "placement_id": placement_id,
                                    "document": placement.document_id,
                                    "start": start,
                                    "end": end,
                                })
                            })
                        })
                        .collect();
                    map.insert(
                        "span".into(),
                        spans.first().map_or(serde_json::Value::Null, |span| {
                            serde_json::json!({
                                "start": span.get("start").cloned().unwrap_or(serde_json::Value::Null),
                                "end": span.get("end").cloned().unwrap_or(serde_json::Value::Null),
                            })
                        }),
                    );
                    map.insert("spans".into(), serde_json::json!(spans));

                    let parent_facts: Vec<Option<String>> = placements
                        .iter()
                        .map(|(placement_id, _)| {
                            edges
                                .get(placement_id)
                                .map(|edge| edge.parent_message_id.clone())
                        })
                        .collect();
                    let parent = match parent_facts.first() {
                        Some(first) if parent_facts.iter().all(|fact| fact == first) => {
                            first.clone()
                        }
                        _ => None,
                    };
                    map.insert(
                        "parent".into(),
                        parent.map_or(serde_json::Value::Null, serde_json::Value::String),
                    );

                    let parent_native_facts: Vec<Option<String>> = placements
                        .iter()
                        .map(|(placement_id, _)| {
                            edges
                                .get(placement_id)
                                .and_then(|edge| edge.parent_native_id.clone())
                        })
                        .collect();
                    let parent_native_id = match parent_native_facts.first() {
                        Some(first) if parent_native_facts.iter().all(|fact| fact == first) => {
                            first.clone()
                        }
                        _ => None,
                    };
                    map.insert(
                        "parent_native_id".into(),
                        parent_native_id.map_or(serde_json::Value::Null, serde_json::Value::String),
                    );

                    let is_sidechain = match placements.first() {
                        Some((_, first))
                            if placements.iter().all(|(_, placement)| {
                                placement.is_sidechain == first.is_sidechain
                            }) =>
                        {
                            serde_json::Value::Bool(first.is_sidechain)
                        }
                        _ => serde_json::Value::Null,
                    };
                    map.insert("is_sidechain".into(), is_sidechain);
                }
                IdKind::Session => {
                    let placements = placements_by_session
                        .get(&entity_id)
                        .cloned()
                        .unwrap_or_default();
                    if placements.is_empty()
                        && map
                            .get("messages")
                            .and_then(serde_json::Value::as_array)
                            .is_some_and(|messages| !messages.is_empty())
                    {
                        continue;
                    }
                    let mut seen_messages = BTreeSet::new();
                    let mut messages = Vec::new();
                    let mut documents = session_document_claims
                        .remove(&entity_id)
                        .unwrap_or_default();
                    for (_, placement) in placements {
                        documents.insert(placement.document_id);
                        if seen_messages.insert(placement.message_id.clone()) {
                            messages.push(placement.message_id);
                        }
                    }
                    let documents: Vec<String> = documents.into_iter().collect();
                    map.insert(
                        "document".into(),
                        documents
                            .first()
                            .cloned()
                            .map_or(serde_json::Value::Null, serde_json::Value::String),
                    );
                    map.insert("documents".into(), serde_json::json!(documents));
                    map.insert("messages".into(), serde_json::json!(messages));
                }
                _ => unreachable!(),
            }

            let payload = serde_json::to_vec(&serde_json::Value::Object(map)).map_err(backend)?;
            // Skip the write when the rebuilt aliases equal the stored bytes:
            // regeneration must not rewrite the catalog (and inflate the WAL)
            // on every commit once aliases are stable.
            let stored: Option<Vec<u8>> = tx
                .query_row(
                    "SELECT payload FROM catalog WHERE id = ?1",
                    [&entity_id],
                    |row| row.get(0),
                )
                .optional()
                .map_err(backend)?;
            if stored.as_deref() != Some(payload.as_slice()) {
                tx.execute(
                    "UPDATE catalog SET payload = ?2 WHERE id = ?1",
                    rusqlite::params![entity_id, payload],
                )
                .map_err(backend)?;
            }
        }
        Ok(())
    }

    fn source_batches_are_current(
        &self,
        upserts: &[(StableId, Vec<u8>, String)],
        relations: &RelationManifests,
    ) -> PortResult<bool> {
        if !self.batch_is_current_with_derived_context(upserts, true)? {
            return Ok(false);
        }
        let stored_placements = self.stored_placements()?;
        let stored_edges = self.stored_edges()?;
        let stored_activities = self.stored_activities()?;
        for upsert in &relations.relation_upserts {
            let current = match upsert {
                RelationUpsertManifest::Placement(placement) => stored_placements
                    .get(placement.id.as_str())
                    .is_some_and(|stored| stored.matches(placement)),
                RelationUpsertManifest::Edge(edge) => stored_edges
                    .get(edge.child_placement_id.as_str())
                    .is_some_and(|stored| stored.matches(edge)),
                RelationUpsertManifest::Activity(activity) => stored_activities
                    .get(&activity.activity_id)
                    .is_some_and(|stored| stored.matches(activity)),
            };
            if !current {
                return Ok(false);
            }
        }
        for delete in &relations.relation_deletes {
            let exists = match delete {
                RelationDeleteManifest::Placement(id) => {
                    stored_placements.contains_key(id.as_str())
                }
                RelationDeleteManifest::Edge(id) => stored_edges.contains_key(id.as_str()),
                RelationDeleteManifest::Activity(activity_id) => {
                    stored_activities.contains_key(activity_id)
                }
            };
            if exists {
                return Ok(false);
            }
        }

        let entity_state = self.source_entity_membership_state()?;
        let placement_state = self.source_placement_membership_state()?;
        let activity_state = self.source_activity_membership_state()?;
        let conn = self.conn.borrow();
        for replacement in &relations.source_replacements {
            let expected_entities: BTreeMap<String, Option<String>> = replacement
                .entity_memberships
                .iter()
                .map(|membership| (membership.entity_id.clone(), membership.document_id.clone()))
                .collect();
            if entity_state
                .get(&replacement.source_path)
                .cloned()
                .unwrap_or_default()
                != expected_entities
            {
                return Ok(false);
            }
            let expected_placements: BTreeSet<String> = replacement
                .placement_ids
                .iter()
                .map(|id| id.as_str().to_string())
                .collect();
            if placement_state
                .get(&replacement.source_path)
                .cloned()
                .unwrap_or_default()
                != expected_placements
            {
                return Ok(false);
            }
            let expected_activity_ids: BTreeSet<String> =
                replacement.activity_ids.iter().cloned().collect();
            if activity_state
                .get(&replacement.source_path)
                .cloned()
                .unwrap_or_default()
                != expected_activity_ids
            {
                return Ok(false);
            }
            let stored_scan: Option<(Option<i64>, Option<String>, Option<String>)> = conn
                .query_row(
                    "SELECT len_bytes, fingerprint, provider_id
                     FROM source_scans WHERE source_path = ?1",
                    [&replacement.source_path],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .optional()
                .map_err(backend)?;
            let Some((stored_len, stored_fingerprint, stored_provider_id)) = stored_scan else {
                return Ok(false);
            };
            // 与 sources_are_current 同口径：指纹缓存参与 no-op 判定。字节已变而
            // 缓存未更新的源必须走提交路径重写 source_scans，否则指纹缓存永不收敛。
            if replacement.len_bytes != stored_len
                || replacement.fingerprint.as_deref() != stored_fingerprint.as_deref()
            {
                return Ok(false);
            }
            if let Some(incoming_provider_id) = replacement.provider_id.as_deref()
                && stored_provider_id.as_deref() != Some(incoming_provider_id)
            {
                return Ok(false);
            }
            let relation_complete: bool = conn
                .query_row(
                    "SELECT EXISTS(
                         SELECT 1 FROM source_relation_scans WHERE source_path = ?1
                     )",
                    [&replacement.source_path],
                    |row| row.get(0),
                )
                .map_err(backend)?;
            if relation_complete != replacement.relation_complete {
                return Ok(false);
            }
            // 与 sources_are_current 同口径：声明变化同样必须走提交路径。
            let stored_resume = stored_resume_claim(&conn, &replacement.source_path)?;
            let expected_resume = replacement
                .resume_claim
                .as_ref()
                .map(StoredResumeClaim::from_claim);
            if stored_resume != expected_resume {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// 读回当前活动 generation（v2 起可用）。
    pub fn active_generation(&self) -> PortResult<u64> {
        let conn = self.conn.borrow();
        let g: i64 = conn
            .query_row(
                "SELECT active_generation FROM store_metadata WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .map_err(backend)?;
        u64::try_from(g).map_err(backend)
    }

    /// 阶段一（durable intent）：写入一条 `building` outbox 行并提交。
    ///
    /// Durable outbox 状态机的第一个 durable point——在任何 catalog/FTS
    /// 变更落盘之前，先持久化"应该构建什么"（upsert/delete 集合 + digest）。
    /// 此后崩溃，恢复只会看到一条无副作用的 `building` 行并将其 `aborted`。
    ///
    /// `base_generation` 必须等于当前活动 generation，否则说明并发写者抢先推进过
    /// generation，本次 intent 作废（CAS 前置条件）。
    pub fn begin_index_batch(
        &self,
        upserts: &[(StableId, Vec<u8>, String)],
        deletes: &[StableId],
    ) -> PortResult<PendingIndexBatch> {
        self.begin_index_batch_with_relations(upserts, deletes, &RelationManifests::default())
    }

    fn begin_index_batch_with_relations(
        &self,
        upserts: &[(StableId, Vec<u8>, String)],
        deletes: &[StableId],
        relations: &RelationManifests,
    ) -> PortResult<PendingIndexBatch> {
        let base = self.active_generation()?;
        let target = base
            .checked_add(1)
            .ok_or_else(|| PortError::Backend("generation overflow".into()))?;
        let target_sql = i64::try_from(target).map_err(backend)?;
        let base_sql = i64::try_from(base).map_err(backend)?;
        let op = operation_id()?;
        let manifest = batch_manifest(upserts, deletes, relations)?;
        let upsert_json = serde_json::to_string(&manifest.upsert_ids).map_err(backend)?;
        let delete_json = serde_json::to_string(&manifest.delete_ids).map_err(backend)?;
        let conn = self.conn.borrow();
        conn.execute(
            "INSERT INTO index_batches(
                 operation_id, base_generation, target_generation, state,
                 operation_digest, upsert_ids_json, delete_ids_json,
                 relation_upserts_json, relation_deletes_json,
                 source_replacements_json, durable_point, created_at_ms
             ) VALUES(
                 ?1, ?2, ?3, 'building', ?4, ?5, ?6, ?7, ?8, ?9, 'intent', ?10
             )",
            rusqlite::params![
                op,
                base_sql,
                target_sql,
                manifest.operation_digest,
                upsert_json,
                delete_json,
                manifest.relation_upserts_json,
                manifest.relation_deletes_json,
                manifest.source_replacements_json,
                unix_ms()?,
            ],
        )
        .map_err(backend)?;
        Ok(PendingIndexBatch {
            operation_id: op,
            base_generation: base,
            target_generation: target,
            operation_digest: manifest.operation_digest,
        })
    }

    /// 阶段二（apply + activate）：在单个事务内应用 catalog+FTS 变更、推进活动
    /// generation，并把 outbox 行标记为 `activated`。
    ///
    /// FTS5 单存储下 catalog 与 FTS 同事务域提交，故 `catalog_committed` 与
    /// `search_built` 合为一个 durable point；generation 切换也在同一事务，
    /// 因此不存在"搜索已建但未激活"的中间崩溃窗口。
    ///
    /// CAS 前置：`active_generation == pending.base_generation`。不匹配则拒绝，
    /// 防止旧基线覆盖更新的同步结果。
    pub fn commit_index_batch(
        &self,
        pending: &PendingIndexBatch,
        upserts: &[(StableId, Vec<u8>, String)],
        deletes: &[StableId],
    ) -> PortResult<()> {
        self.commit_index_batch_with_relations(
            pending,
            upserts,
            deletes,
            &RelationManifests::default(),
        )
    }

    /// 事务内校验 pending 句柄仍可安全激活：generation CAS + intent 行状态 + manifest 匹配。
    ///
    /// 从 [`commit_index_batch_with_relations`](Self::commit_index_batch_with_relations) 抽出，
    /// 使 rebuild 路径复用同一套“不覆盖更新基线 / 不与 durable intent 分歧”的前置检查。
    fn verify_pending_in_tx(
        tx: &rusqlite::Transaction<'_>,
        pending: &PendingIndexBatch,
        upserts: &[(StableId, Vec<u8>, String)],
        deletes: &[StableId],
        relations: &RelationManifests,
    ) -> PortResult<()> {
        // CAS：活动 generation 必须仍等于 intent 记录的 base，否则中止本批次。
        let current: i64 = tx
            .query_row(
                "SELECT active_generation FROM store_metadata WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .map_err(backend)?;
        if current as u64 != pending.base_generation {
            return Err(PortError::Backend(format!(
                "generation CAS failed: active {current} != expected base {}",
                pending.base_generation
            )));
        }
        // intent 行及其完整 manifest 必须仍与 pending handle 匹配。
        let (
            declared_base,
            declared_target,
            state,
            declared_digest,
            declared_upserts,
            declared_deletes,
            declared_relation_upserts,
            declared_relation_deletes,
            declared_source_replacements,
        ): (
            i64,
            i64,
            String,
            String,
            String,
            String,
            String,
            String,
            String,
        ) = tx
            .query_row(
                "SELECT base_generation, target_generation, state, operation_digest,
                        upsert_ids_json, delete_ids_json, relation_upserts_json,
                        relation_deletes_json, source_replacements_json
                 FROM index_batches WHERE operation_id = ?1",
                [&pending.operation_id],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                        row.get(7)?,
                        row.get(8)?,
                    ))
                },
            )
            .map_err(backend)?;
        if state != "building" {
            return Err(PortError::Backend(format!(
                "index batch {} is in state {state}, expected building",
                pending.operation_id
            )));
        }
        let actual = batch_manifest(upserts, deletes, relations)?;
        let actual_upserts = serde_json::to_string(&actual.upsert_ids).map_err(backend)?;
        let actual_deletes = serde_json::to_string(&actual.delete_ids).map_err(backend)?;
        let handle_matches = declared_base == pending.base_generation as i64
            && declared_target == pending.target_generation as i64
            && declared_digest == pending.operation_digest;
        if !handle_matches
            || declared_digest != actual.operation_digest
            || declared_upserts != actual_upserts
            || declared_deletes != actual_deletes
            || declared_relation_upserts != actual.relation_upserts_json
            || declared_relation_deletes != actual.relation_deletes_json
            || declared_source_replacements != actual.source_replacements_json
        {
            return Err(PortError::Backend(format!(
                "index batch {} payload does not match durable intent",
                pending.operation_id
            )));
        }
        Ok(())
    }

    /// 收集本批被触碰的 placement id 归属的 Session 集合（分块 IN，无 N+1）。
    fn collect_placement_sessions(
        conn: &Connection,
        placement_ids: &[String],
        sessions: &mut BTreeSet<String>,
    ) -> PortResult<()> {
        for chunk in chunk_ids(placement_ids) {
            let placeholders = chunk.iter().map(|_| "?").collect::<Vec<_>>().join(",");
            let mut stmt = conn
                .prepare(&format!(
                    "SELECT DISTINCT session_id FROM message_placements
                     WHERE placement_id IN ({placeholders})"
                ))
                .map_err(backend)?;
            let rows = stmt
                .query_map(rusqlite::params_from_iter(chunk.iter()), |row| {
                    row.get::<_, String>(0)
                })
                .map_err(backend)?;
            for row in rows {
                sessions.insert(row.map_err(backend)?);
            }
        }
        Ok(())
    }

    /// 收集本批被触碰的 message id 归属的 Session 集合（分块 IN，无 N+1）。
    fn collect_message_sessions(
        conn: &Connection,
        message_ids: &[String],
        sessions: &mut BTreeSet<String>,
    ) -> PortResult<()> {
        for chunk in chunk_ids(message_ids) {
            let placeholders = chunk.iter().map(|_| "?").collect::<Vec<_>>().join(",");
            let mut stmt = conn
                .prepare(&format!(
                    "SELECT DISTINCT session_id FROM message_placements
                     WHERE message_id IN ({placeholders})"
                ))
                .map_err(backend)?;
            let rows = stmt
                .query_map(rusqlite::params_from_iter(chunk.iter()), |row| {
                    row.get::<_, String>(0)
                })
                .map_err(backend)?;
            for row in rows {
                sessions.insert(row.map_err(backend)?);
            }
        }
        Ok(())
    }

    /// 收集本批 source replacement 触碰的 Session 集合（分块 IN，无 N+1）。
    fn collect_resume_claim_sessions(
        conn: &Connection,
        source_paths: &[String],
        sessions: &mut BTreeSet<String>,
    ) -> PortResult<()> {
        for chunk in chunk_ids(source_paths) {
            let placeholders = chunk.iter().map(|_| "?").collect::<Vec<_>>().join(",");
            let mut stmt = conn
                .prepare(&format!(
                    "SELECT DISTINCT session_id FROM source_session_resume_claims
                     WHERE source_path IN ({placeholders})"
                ))
                .map_err(backend)?;
            let rows = stmt
                .query_map(rusqlite::params_from_iter(chunk.iter()), |row| {
                    row.get::<_, String>(0)
                })
                .map_err(backend)?;
            for row in rows {
                sessions.insert(row.map_err(backend)?);
            }
        }
        Ok(())
    }

    /// Build one Session's bounded search text from authoritative relational
    /// state. A representative placement is required so a metadata match can be
    /// returned as an existing Message `SearchHit` without fabricating an id.
    fn session_search_text(conn: &Connection, session_wire: &str) -> PortResult<Option<String>> {
        let session_exists: bool = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM catalog WHERE id = ?1)",
                [session_wire],
                |row| row.get(0),
            )
            .map_err(backend)?;
        if !session_exists {
            return Ok(None);
        }

        let first_user_text = {
            let mut stmt = conn
                .prepare(
                    "SELECT catalog.payload
                     FROM message_placements
                     JOIN catalog ON catalog.id = message_placements.message_id
                     WHERE message_placements.session_id = ?1
                     ORDER BY asg_instant_sort_key(
                                  CASE WHEN json_valid(catalog.payload)
                                       THEN json_extract(catalog.payload, '$.timestamp') END
                              ) IS NULL,
                              asg_instant_sort_key(
                                  CASE WHEN json_valid(catalog.payload)
                                       THEN json_extract(catalog.payload, '$.timestamp') END
                              ),
                              message_placements.document_id,
                              message_placements.source_ordinal,
                              message_placements.placement_id",
                )
                .map_err(backend)?;
            let rows = stmt
                .query_map([session_wire], |row| row.get::<_, Vec<u8>>(0))
                .map_err(backend)?;
            let mut first_user_text = None;
            for row in rows {
                let payload = row.map_err(backend)?;
                if let Ok(value) = serde_json::from_slice::<serde_json::Value>(&payload)
                    && value.get("role").and_then(serde_json::Value::as_str) == Some("user")
                    && let Some(text) = value.get("text").and_then(serde_json::Value::as_str)
                    && !text.is_empty()
                {
                    first_user_text = Some(
                        text.chars()
                            .take(SESSION_SEARCH_FIELD_CHARS)
                            .collect::<String>(),
                    );
                    break;
                }
            }
            first_user_text
        };

        // Claims for one canonical Session must agree exactly. Conflict is
        // privacy-sensitive, so fail closed and index none of their values.
        let resolved_claim = {
            let mut stmt = conn
                .prepare(
                    "SELECT session_id, provider_id, provider_session_id,
                            provider_session_id_state, original_working_directory,
                            original_working_directory_state, pair_observed
                     FROM source_session_resume_claims
                     WHERE session_id = ?1",
                )
                .map_err(backend)?;
            let rows = stmt
                .query_map([session_wire], |row| {
                    Ok(StoredResumeClaim {
                        session_id: row.get(0)?,
                        provider_id: row.get(1)?,
                        provider_session_id: row.get(2)?,
                        provider_session_id_state: row.get(3)?,
                        original_working_directory: row.get(4)?,
                        original_working_directory_state: row.get(5)?,
                        pair_observed: row.get(6)?,
                    })
                })
                .map_err(backend)?;
            let mut claim: Option<StoredResumeClaim> = None;
            let mut conflicting = false;
            for row in rows {
                let next = row.map_err(backend)?;
                if claim.as_ref().is_some_and(|current| current != &next) {
                    conflicting = true;
                    break;
                }
                claim = Some(next);
            }
            if conflicting { None } else { claim }
        };

        let mut fields = Vec::new();
        if let Some(claim) = resolved_claim
            && claim.provider_session_id_state == "resolved"
            && let Some(provider_session_id) = claim.provider_session_id
            && !provider_session_id.is_empty()
        {
            fields.push(
                provider_session_id
                    .chars()
                    .take(SESSION_SEARCH_FIELD_CHARS)
                    .collect(),
            );
            if claim.pair_observed
                && claim.original_working_directory_state == "resolved"
                && let Some(directory) = claim.original_working_directory
                && !directory.is_empty()
            {
                fields.push(directory.chars().take(SESSION_SEARCH_FIELD_CHARS).collect());
            }
        }
        if let Some(text) = first_user_text {
            fields.push(text);
        }
        if fields.is_empty() {
            Ok(None)
        } else {
            Ok(Some(fields.join("\n")))
        }
    }

    fn rebuild_session_search_row_in_tx(
        tx: &rusqlite::Transaction<'_>,
        session_wire: &str,
    ) -> PortResult<()> {
        tx.execute(
            "DELETE FROM session_fts
             WHERE rowid = (
                 SELECT fts_rowid FROM session_fts_ids WHERE session_wire = ?1
             )",
            [session_wire],
        )
        .map_err(backend)?;
        tx.execute(
            "DELETE FROM session_fts_ids WHERE session_wire = ?1",
            [session_wire],
        )
        .map_err(backend)?;
        if let Some(text) = Self::session_search_text(tx, session_wire)? {
            tx.execute(
                "INSERT INTO session_fts(session_wire, text) VALUES(?1, ?2)",
                rusqlite::params![session_wire, bigram_cjk(&text)],
            )
            .map_err(backend)?;
            tx.execute(
                "INSERT INTO session_fts_ids(session_wire, fts_rowid) VALUES(?1, ?2)",
                rusqlite::params![session_wire, tx.last_insert_rowid()],
            )
            .map_err(backend)?;
        }
        Ok(())
    }

    fn rebuild_all_session_search_in_tx(tx: &rusqlite::Transaction<'_>) -> PortResult<()> {
        tx.execute("DELETE FROM session_fts", []).map_err(backend)?;
        tx.execute("DELETE FROM session_fts_ids", [])
            .map_err(backend)?;
        let sessions = {
            let mut stmt = tx
                .prepare("SELECT id FROM catalog WHERE id LIKE 'ses_v1_%' ORDER BY id")
                .map_err(backend)?;
            let rows = stmt
                .query_map([], |row| row.get::<_, String>(0))
                .map_err(backend)?;
            let mut sessions = Vec::new();
            for row in rows {
                sessions.push(row.map_err(backend)?);
            }
            sessions
        };
        for session_wire in sessions {
            Self::rebuild_session_search_row_in_tx(tx, &session_wire)?;
        }
        Ok(())
    }

    fn commit_index_batch_with_relations(
        &self,
        pending: &PendingIndexBatch,
        upserts: &[(StableId, Vec<u8>, String)],
        deletes: &[StableId],
        relations: &RelationManifests,
    ) -> PortResult<()> {
        let mut conn = self.conn.borrow_mut();
        let tx = conn.transaction().map_err(backend)?;
        Self::verify_pending_in_tx(&tx, pending, upserts, deletes, relations)?;

        // Session 元数据投影（schema v11）：收集本批触碰的 Session，提交末尾
        // 逐个重建其 `session_fts` 行（删除按 rowid 经边车定位，重插新投影）。
        // 覆盖 upsert/delete 实体、placement 变动（含移动归属的旧主）、以及
        // source replacement 的旧 placement 与 claim 行——与写入路径同事务。
        let mut affected_sessions = BTreeSet::new();
        for id in upserts.iter().map(|(id, _, _)| id).chain(deletes.iter()) {
            match id.kind() {
                IdKind::Session => {
                    affected_sessions.insert(id.as_str().to_string());
                }
                IdKind::Message => {
                    Self::collect_message_sessions(
                        &tx,
                        &[id.as_str().to_string()],
                        &mut affected_sessions,
                    )?;
                }
                IdKind::Document => {}
                IdKind::Source => {}
            }
        }
        let mut old_placement_ids = Vec::new();
        let mut source_paths = Vec::new();
        for delete in &relations.relation_deletes {
            if let RelationDeleteManifest::Placement(placement_id) = delete {
                old_placement_ids.push(placement_id.as_str().to_string());
            }
        }
        for upsert in &relations.relation_upserts {
            if let RelationUpsertManifest::Placement(placement) = upsert {
                // An upsert can move an existing placement to another Session;
                // read its old owner before the INSERT ... ON CONFLICT update.
                old_placement_ids.push(placement.id.as_str().to_string());
                affected_sessions.insert(placement.session_id.as_str().to_string());
                Self::collect_message_sessions(
                    &tx,
                    &[placement.message_id.as_str().to_string()],
                    &mut affected_sessions,
                )?;
            }
        }
        for source in &relations.source_replacements {
            source_paths.push(source.source_path.clone());
            if let Some(claim) = &source.resume_claim {
                affected_sessions.insert(claim.session_id.clone());
            }
            let mut stmt = tx
                .prepare(
                    "SELECT placement_id FROM source_placement_membership
                     WHERE source_path = ?1",
                )
                .map_err(backend)?;
            let rows = stmt
                .query_map([&source.source_path], |row| row.get::<_, String>(0))
                .map_err(backend)?;
            for row in rows {
                old_placement_ids.push(row.map_err(backend)?);
            }
        }
        Self::collect_placement_sessions(&tx, &old_placement_ids, &mut affected_sessions)?;
        Self::collect_resume_claim_sessions(&tx, &source_paths, &mut affected_sessions)?;

        // 批量写入：同一事务内以多行 VALUES 语句替代逐行 prepared execute
        // （借鉴 hstry bulk_insert_messages_in_tx，MIT，
        // hstry/crates/hstry-core/src/db.rs:2990）。200K 实体 × 5 条语句的
        // 逐行 execute 支配了首次 ingest 的常数因子；批量后每 100 实体只发
        // 5 条语句。Scoped so the borrow ends before the relation/source
        // loops below.
        {
            const _: () = assert!(2 * BULK_INSERT_ROWS_PER_CHUNK <= 950);
            for chunk in upserts.chunks(BULK_INSERT_ROWS_PER_CHUNK) {
                let sql = format!(
                    "INSERT INTO catalog(id, payload) VALUES {}
                     ON CONFLICT(id) DO UPDATE SET payload = excluded.payload",
                    multi_row_values(chunk.len(), 2)
                );
                let rows: Vec<(String, &Vec<u8>)> = chunk
                    .iter()
                    .map(|(id, payload, _)| (id.as_str().to_string(), payload))
                    .collect();
                let params: Vec<&dyn rusqlite::ToSql> = rows
                    .iter()
                    .flat_map(|(wire, payload)| {
                        let c0: &dyn rusqlite::ToSql = wire;
                        let c1: &dyn rusqlite::ToSql = payload;
                        [c0, c1]
                    })
                    .collect();
                tx.execute(&sql, rusqlite::params_from_iter(params))
                    .map_err(backend)?;
            }
            // fts 行与 fts_ids 身份边车的批量维护（含按 rowid 的旧行删除）：
            // 与逐行路径同语义，rowid 显式分配（见 batch_upsert_fts_in_tx）。
            Self::batch_upsert_fts_in_tx(&tx, upserts)?;
            for chunk in deletes.chunks(BULK_INSERT_ROWS_PER_CHUNK) {
                let ids: Vec<&str> = chunk.iter().map(|id| id.as_str()).collect();
                let placeholders = in_placeholders(ids.len());
                tx.execute(
                    &format!("DELETE FROM catalog WHERE id IN ({placeholders})"),
                    rusqlite::params_from_iter(ids.iter().copied()),
                )
                .map_err(backend)?;
                tx.execute(
                    &format!(
                        "DELETE FROM fts
                         WHERE rowid IN (
                             SELECT fts_rowid FROM fts_ids WHERE wire_id IN ({placeholders})
                         )"
                    ),
                    rusqlite::params_from_iter(ids.iter().copied()),
                )
                .map_err(backend)?;
                tx.execute(
                    &format!("DELETE FROM fts_ids WHERE wire_id IN ({placeholders})"),
                    rusqlite::params_from_iter(ids.iter().copied()),
                )
                .map_err(backend)?;
            }
        }

        for delete in &relations.relation_deletes {
            match delete {
                RelationDeleteManifest::Edge(placement_id) => {
                    tx.execute(
                        "DELETE FROM message_edges WHERE child_placement_id = ?1",
                        [placement_id.as_str()],
                    )
                    .map_err(backend)?;
                }
                RelationDeleteManifest::Placement(placement_id) => {
                    tx.execute(
                        "DELETE FROM message_placements WHERE placement_id = ?1",
                        [placement_id.as_str()],
                    )
                    .map_err(backend)?;
                }
                RelationDeleteManifest::Activity(activity_id) => {
                    tx.execute(
                        "DELETE FROM tool_activities WHERE activity_id = ?1",
                        [activity_id],
                    )
                    .map_err(backend)?;
                }
            }
        }
        // 关系行 upsert：多行批量（借鉴 hstry bulk_insert_messages_in_tx，MIT，
        // hstry/crates/hstry-core/src/db.rs:2990）。message_placements 8 列 ×
        // 100 行 = 800 参数，message_edges 4 列 × 100 行 = 400 参数，均低于
        // SQLite 默认 999 变量上限（模块级编译期断言守住上限）。
        {
            let mut placement_rows: Vec<PlacementInsertRow<'_>> = Vec::new();
            for upsert in &relations.relation_upserts {
                if let RelationUpsertManifest::Placement(placement) = upsert {
                    let (byte_start, byte_end) = match &placement.span {
                        Some(span) => (
                            Some(i64::try_from(span.start).map_err(backend)?),
                            Some(i64::try_from(span.end).map_err(backend)?),
                        ),
                        None => (None, None),
                    };
                    placement_rows.push((
                        placement.id.as_str(),
                        placement.session_id.as_str(),
                        placement.source_document_id.as_str(),
                        placement.message_id.as_str(),
                        i64::from(placement.source_ordinal),
                        i64::from(placement.is_sidechain),
                        byte_start,
                        byte_end,
                    ));
                }
            }
            const _: () = assert!(8 * BULK_INSERT_ROWS_PER_CHUNK <= 950);
            for chunk in placement_rows.chunks(BULK_INSERT_ROWS_PER_CHUNK) {
                let sql = format!(
                    "INSERT INTO message_placements(
                         placement_id, session_id, document_id, message_id,
                         source_ordinal, is_sidechain, byte_start, byte_end
                     ) VALUES {}
                     ON CONFLICT(placement_id) DO UPDATE SET
                         session_id = excluded.session_id,
                         document_id = excluded.document_id,
                         message_id = excluded.message_id,
                         source_ordinal = excluded.source_ordinal,
                         is_sidechain = excluded.is_sidechain,
                         byte_start = excluded.byte_start,
                         byte_end = excluded.byte_end",
                    multi_row_values(chunk.len(), 8)
                );
                let params: Vec<&dyn rusqlite::ToSql> = chunk
                    .iter()
                    .flat_map(|row| {
                        let c0: &dyn rusqlite::ToSql = &row.0;
                        let c1: &dyn rusqlite::ToSql = &row.1;
                        let c2: &dyn rusqlite::ToSql = &row.2;
                        let c3: &dyn rusqlite::ToSql = &row.3;
                        let c4: &dyn rusqlite::ToSql = &row.4;
                        let c5: &dyn rusqlite::ToSql = &row.5;
                        let c6: &dyn rusqlite::ToSql = &row.6;
                        let c7: &dyn rusqlite::ToSql = &row.7;
                        [c0, c1, c2, c3, c4, c5, c6, c7]
                    })
                    .collect();
                tx.execute(&sql, rusqlite::params_from_iter(params))
                    .map_err(backend)?;
            }
            let mut edge_rows: Vec<(&str, &str, Option<&str>, &str)> = Vec::new();
            for upsert in &relations.relation_upserts {
                if let RelationUpsertManifest::Edge(edge) = upsert {
                    edge_rows.push((
                        edge.child_placement_id.as_str(),
                        edge.parent_message_id.as_str(),
                        edge.parent_native_id.as_deref(),
                        edge.relation.as_str(),
                    ));
                }
            }
            const _: () = assert!(4 * BULK_INSERT_ROWS_PER_CHUNK <= 950);
            for chunk in edge_rows.chunks(BULK_INSERT_ROWS_PER_CHUNK) {
                let sql = format!(
                    "INSERT INTO message_edges(
                         child_placement_id, parent_message_id,
                         parent_native_id, relation
                     ) VALUES {}
                     ON CONFLICT(child_placement_id) DO UPDATE SET
                         parent_message_id = excluded.parent_message_id,
                         parent_native_id = excluded.parent_native_id,
                         relation = excluded.relation",
                    multi_row_values(chunk.len(), 4)
                );
                let params: Vec<&dyn rusqlite::ToSql> = chunk
                    .iter()
                    .flat_map(|row| {
                        let c0: &dyn rusqlite::ToSql = &row.0;
                        let c1: &dyn rusqlite::ToSql = &row.1;
                        let c2: &dyn rusqlite::ToSql = &row.2;
                        let c3: &dyn rusqlite::ToSql = &row.3;
                        [c0, c1, c2, c3]
                    })
                    .collect();
                tx.execute(&sql, rusqlite::params_from_iter(params))
                    .map_err(backend)?;
            }
        }

        // 工具活动 upsert（v12）：逐行 upsert。活动行是内容寻址的（activity_id），
        // 同一事实跨源去重；行数由工具调用数决定，量级远小于 placements/edges。
        for upsert in &relations.relation_upserts {
            if let RelationUpsertManifest::Activity(activity) = upsert {
                tx.execute(
                    "INSERT INTO tool_activities(
                         activity_id, message_id, kind, actor, name, target, status
                     ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7)
                     ON CONFLICT(activity_id) DO UPDATE SET
                         message_id = excluded.message_id,
                         kind = excluded.kind,
                         actor = excluded.actor,
                         name = excluded.name,
                         target = excluded.target,
                         status = excluded.status",
                    rusqlite::params![
                        activity.activity_id,
                        activity.message_id,
                        activity.kind,
                        activity.actor,
                        activity.name,
                        activity.target,
                        activity.status,
                    ],
                )
                .map_err(backend)?;
            }
        }

        for source in &relations.source_replacements {
            tx.execute(
                "DELETE FROM source_membership WHERE source_path = ?1",
                [&source.source_path],
            )
            .map_err(backend)?;
            // 每源成员行可能上千，多行批量插入（同 hstry bulk_insert 模式，
            // 3 列 × 100 行 = 300 参数）。
            const _: () = assert!(3 * BULK_INSERT_ROWS_PER_CHUNK <= 950);
            for chunk in source.entity_memberships.chunks(BULK_INSERT_ROWS_PER_CHUNK) {
                let sql = format!(
                    "INSERT INTO source_membership(source_path, message_id, document_id)
                     VALUES {}",
                    multi_row_values(chunk.len(), 3)
                );
                let params: Vec<&dyn rusqlite::ToSql> = chunk
                    .iter()
                    .flat_map(|membership| {
                        let c0: &dyn rusqlite::ToSql = &source.source_path;
                        let c1: &dyn rusqlite::ToSql = &membership.entity_id;
                        let c2: &dyn rusqlite::ToSql = &membership.document_id;
                        [c0, c1, c2]
                    })
                    .collect();
                tx.execute(&sql, rusqlite::params_from_iter(params))
                    .map_err(backend)?;
            }
            tx.execute(
                "DELETE FROM source_placement_membership WHERE source_path = ?1",
                [&source.source_path],
            )
            .map_err(backend)?;
            const _: () = assert!(2 * BULK_INSERT_ROWS_PER_CHUNK <= 950);
            for chunk in source.placement_ids.chunks(BULK_INSERT_ROWS_PER_CHUNK) {
                let sql = format!(
                    "INSERT INTO source_placement_membership(source_path, placement_id)
                     VALUES {}",
                    multi_row_values(chunk.len(), 2)
                );
                let rows: Vec<String> = chunk
                    .iter()
                    .map(|placement_id| placement_id.as_str().to_string())
                    .collect();
                let params: Vec<&dyn rusqlite::ToSql> = rows
                    .iter()
                    .flat_map(|placement_id| {
                        let c0: &dyn rusqlite::ToSql = &source.source_path;
                        let c1: &dyn rusqlite::ToSql = placement_id;
                        [c0, c1]
                    })
                    .collect();
                tx.execute(&sql, rusqlite::params_from_iter(params))
                    .map_err(backend)?;
            }
            // 工具活动成员（v12）：与 placement 同一生命周期——先清旧声明，
            // 本批带活动才写新行；无活动即清除（source 不再观察/移除）。
            tx.execute(
                "DELETE FROM tool_activity_membership WHERE source_path = ?1",
                [&source.source_path],
            )
            .map_err(backend)?;
            for activity_id in &source.activity_ids {
                tx.execute(
                    "INSERT INTO tool_activity_membership(source_path, activity_id)
                     VALUES(?1, ?2)",
                    rusqlite::params![&source.source_path, activity_id],
                )
                .map_err(backend)?;
            }
            tx.execute(
                "INSERT INTO source_scans(source_path, scanned_at_ms, len_bytes, fingerprint, provider_id)
                 VALUES(?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(source_path) DO UPDATE SET
                     scanned_at_ms = excluded.scanned_at_ms,
                     len_bytes = excluded.len_bytes,
                     fingerprint = excluded.fingerprint,
                     provider_id = COALESCE(excluded.provider_id, source_scans.provider_id)",
                rusqlite::params![
                    &source.source_path,
                    unix_ms()?,
                    source.len_bytes,
                    source.fingerprint,
                    source.provider_id,
                ],
            )
            .map_err(backend)?;
            if source.relation_complete {
                tx.execute(
                    "INSERT INTO source_relation_scans(source_path, relation_schema_version)
                     VALUES(?1, ?2)
                     ON CONFLICT(source_path) DO UPDATE SET
                         relation_schema_version = excluded.relation_schema_version",
                    rusqlite::params![&source.source_path, RELATION_SCHEMA_VERSION],
                )
                .map_err(backend)?;
            } else {
                tx.execute(
                    "DELETE FROM source_relation_scans WHERE source_path = ?1",
                    [&source.source_path],
                )
                .map_err(backend)?;
            }
            // Source-scoped Resume Metadata 声明（ADR-0009）：随 source replacement
            // 同事务原子替换——先清旧声明，本批带声明才写新行；无声明
            // （source 不再观察/移除）即清除，绝不残留旧声明。
            tx.execute(
                "DELETE FROM source_session_resume_claims WHERE source_path = ?1",
                [&source.source_path],
            )
            .map_err(backend)?;
            if let Some(claim) = &source.resume_claim {
                tx.execute(
                    "INSERT INTO source_session_resume_claims(
                         source_path, session_id, provider_id, provider_session_id,
                         provider_session_id_state, original_working_directory,
                         original_working_directory_state, pair_observed
                     ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                    rusqlite::params![
                        &source.source_path,
                        &claim.session_id,
                        &claim.provider_id,
                        &claim.provider_session_id,
                        &claim.provider_session_id_state,
                        &claim.original_working_directory,
                        &claim.original_working_directory_state,
                        i64::from(claim.pair_observed),
                    ],
                )
                .map_err(backend)?;
            }
        }

        let batch_sources: Vec<String> = relations
            .source_replacements
            .iter()
            .map(|replacement| replacement.source_path.clone())
            .collect();
        Self::regenerate_compatibility_aliases_in_tx(&tx, &batch_sources)?;
        for session_wire in affected_sessions {
            Self::rebuild_session_search_row_in_tx(&tx, &session_wire)?;
        }

        // 本批触碰的关系行：只校验这些 id 的引用完整性。
        let mut touched_placements: Vec<String> = Vec::new();
        let mut touched_edges: Vec<String> = Vec::new();
        let mut touched_claims: Vec<String> = Vec::new();
        for source in &relations.source_replacements {
            touched_claims.extend(
                source
                    .placement_ids
                    .iter()
                    .map(|id| id.as_str().to_string()),
            );
        }
        for upsert in &relations.relation_upserts {
            match upsert {
                RelationUpsertManifest::Placement(placement) => {
                    touched_placements.push(placement.id.as_str().to_string());
                }
                RelationUpsertManifest::Edge(edge) => {
                    touched_edges.push(edge.child_placement_id.as_str().to_string());
                }
                // 工具活动不参与 placement/edge 引用完整性校验（独立表）。
                RelationUpsertManifest::Activity(_) => {}
            }
        }
        for delete in &relations.relation_deletes {
            match delete {
                RelationDeleteManifest::Placement(id) => {
                    touched_placements.push(id.as_str().to_string());
                }
                RelationDeleteManifest::Edge(id) => {
                    touched_edges.push(id.as_str().to_string());
                }
                RelationDeleteManifest::Activity(_) => {}
            }
        }
        Self::verify_relational_integrity_in_tx(
            &tx,
            &touched_placements,
            &touched_edges,
            &touched_claims,
        )?;
        // B1 路径（裸 commit_batch/commit_index_batch）只删 catalog 实体、不维护
        // v7 关系行：被删实体若仍被 message_placements/message_edges 引用，会留下
        // 悬空引用，必须在此拒绝（B2 路径的删除按 claimer 推导，天然无悬空）。
        Self::verify_deleted_entities_unreferenced_in_tx(&tx, deletes)?;

        tx.execute(
            "UPDATE store_metadata SET active_generation = ?1 WHERE singleton = 1",
            [pending.target_generation as i64],
        )
        .map_err(backend)?;
        tx.execute(
            "UPDATE index_batches
             SET state = 'activated', durable_point = 'activated', committed_at_ms = ?2
             WHERE operation_id = ?1",
            rusqlite::params![pending.operation_id, unix_ms()?],
        )
        .map_err(backend)?;

        tx.commit().map_err(backend)?;
        Ok(())
    }

    /// 校验本批触碰的关系行引用完整性。
    ///
    /// 只检查本批 upsert/delete 涉及的 placement/edge/claim ids：未触碰行的
    /// 完整性由归纳保持（每次提交维护自身行、删除只删本批 claims）。全表
    /// 扫描版本使每批提交成本 O(全库)，是首次 ingest O(n²) 的来源之一。
    fn verify_relational_integrity_in_tx(
        tx: &rusqlite::Transaction<'_>,
        touched_placement_ids: &[String],
        touched_edge_ids: &[String],
        touched_claim_ids: &[String],
    ) -> PortResult<()> {
        for chunk in chunk_ids(touched_placement_ids) {
            let placeholders = chunk.iter().map(|_| "?").collect::<Vec<_>>().join(",");
            let missing_entity: Option<String> = tx
                .query_row(
                    &format!(
                        "SELECT placement_id
                         FROM message_placements
                         WHERE placement_id IN ({placeholders})
                           AND (NOT EXISTS(
                                    SELECT 1 FROM catalog WHERE id = message_placements.session_id
                                )
                             OR NOT EXISTS(
                                    SELECT 1 FROM catalog WHERE id = message_placements.document_id
                                )
                             OR NOT EXISTS(
                                    SELECT 1 FROM catalog WHERE id = message_placements.message_id
                                ))
                         LIMIT 1"
                    ),
                    rusqlite::params_from_iter(chunk.iter()),
                    |row| row.get(0),
                )
                .optional()
                .map_err(backend)?;
            if missing_entity.is_some() {
                return Err(PortError::Backend(
                    "message placement references a missing catalog entity".into(),
                ));
            }
        }

        for chunk in chunk_ids(touched_edge_ids) {
            let placeholders = chunk.iter().map(|_| "?").collect::<Vec<_>>().join(",");
            let missing_placement: Option<String> = tx
                .query_row(
                    &format!(
                        "SELECT child_placement_id
                         FROM message_edges
                         WHERE child_placement_id IN ({placeholders})
                           AND NOT EXISTS(
                               SELECT 1 FROM message_placements
                               WHERE placement_id = message_edges.child_placement_id
                           )
                         LIMIT 1"
                    ),
                    rusqlite::params_from_iter(chunk.iter()),
                    |row| row.get(0),
                )
                .optional()
                .map_err(backend)?;
            if missing_placement.is_some() {
                return Err(PortError::Backend(
                    "message edge references a missing child placement".into(),
                ));
            }
        }

        for chunk in chunk_ids(touched_claim_ids) {
            let placeholders = chunk.iter().map(|_| "?").collect::<Vec<_>>().join(",");
            let missing_claim: Option<String> = tx
                .query_row(
                    &format!(
                        "SELECT placement_id
                         FROM source_placement_membership
                         WHERE placement_id IN ({placeholders})
                           AND NOT EXISTS(
                               SELECT 1 FROM message_placements
                               WHERE placement_id = source_placement_membership.placement_id
                           )
                         LIMIT 1"
                    ),
                    rusqlite::params_from_iter(chunk.iter()),
                    |row| row.get(0),
                )
                .optional()
                .map_err(backend)?;
            if missing_claim.is_some() {
                return Err(PortError::Backend(
                    "source placement claim references a missing placement".into(),
                ));
            }
        }
        Ok(())
    }

    /// 校验 delete 列表中的 catalog 实体不被任何 v7 关系行引用。
    ///
    /// B1 路径（裸 commit_batch/commit_index_batch）不维护关系行：若被删实体仍被
    /// `message_placements`（session/document/message 任一身份）或 `message_edges`
    /// （parent_message_id）引用，提交会留下悬空引用且事后才被发现。按 chunk 检查
    /// 引用存在性，任一命中即拒绝整批。
    fn verify_deleted_entities_unreferenced_in_tx(
        tx: &rusqlite::Transaction<'_>,
        deletes: &[StableId],
    ) -> PortResult<()> {
        let ids: Vec<&str> = deletes.iter().map(|id| id.as_str()).collect();
        for chunk in chunk_ids(&ids) {
            let placeholders = chunk.iter().map(|_| "?").collect::<Vec<_>>().join(",");
            let dangling_placement: Option<String> = tx
                .query_row(
                    &format!(
                        "SELECT placement_id
                         FROM message_placements
                         WHERE session_id IN ({placeholders})
                            OR document_id IN ({placeholders})
                            OR message_id IN ({placeholders})
                         LIMIT 1"
                    ),
                    rusqlite::params_from_iter(
                        chunk.iter().chain(chunk.iter()).chain(chunk.iter()),
                    ),
                    |row| row.get(0),
                )
                .optional()
                .map_err(backend)?;
            if dangling_placement.is_some() {
                return Err(PortError::Backend(
                    "cannot delete a catalog entity still referenced by message placements".into(),
                ));
            }
            let dangling_resume_claim: Option<String> = tx
                .query_row(
                    &format!(
                        "SELECT source_path
                         FROM source_session_resume_claims
                         WHERE session_id IN ({placeholders})
                         LIMIT 1"
                    ),
                    rusqlite::params_from_iter(chunk.iter()),
                    |row| row.get(0),
                )
                .optional()
                .map_err(backend)?;
            if dangling_resume_claim.is_some() {
                return Err(PortError::Backend(
                    "cannot delete a catalog session still referenced by resume metadata claims"
                        .into(),
                ));
            }
            let dangling_edge: Option<String> = tx
                .query_row(
                    &format!(
                        "SELECT child_placement_id
                         FROM message_edges
                         WHERE parent_message_id IN ({placeholders})
                         LIMIT 1"
                    ),
                    rusqlite::params_from_iter(chunk.iter()),
                    |row| row.get(0),
                )
                .optional()
                .map_err(backend)?;
            if dangling_edge.is_some() {
                return Err(PortError::Backend(
                    "cannot delete a catalog entity still referenced by message edges".into(),
                ));
            }
        }
        Ok(())
    }

    /// 在给定事务内批量维护一批实体的 fts 行与 fts_ids 身份边车。
    ///
    /// 与 [`Self::upsert_fts_row_in_tx`]（单条路径）同语义，但以多行
    /// `INSERT ... VALUES (...),(...),...` 批量执行（借鉴 hstry
    /// `bulk_insert_messages_in_tx`，MIT，hstry/crates/hstry-core/src/db.rs:2990）：
    /// 先按边车记录的 rowid 批量删除旧 fts 行（避免内容列整表扫描），再按
    /// kind 门控——只有 Message 实体进入 fts 全文表，session/document 是
    /// 容器实体，索引其正文会让搜索命中重复计数；非 Message 只保留身份边车
    /// （fts_rowid 为 NULL，按 NULL 定位删除即无操作）。
    ///
    /// fts5 的 rowid 由本函数显式分配（`INSERT INTO fts(rowid, ...)`）：
    /// 多行 INSERT 无法逐行取 `last_insert_rowid()`（只返回最后一行），而
    /// `RETURNING rowid` 在 fts5 上不可用（实测返回 -1）。分配从当前
    /// `MAX(rowid)+1` 起顺序递增；本批次每个 wire_id 至多出现一次且旧行
    /// 已先删除，故不会与存量行或同批其他行冲突。索引侧正文与查询侧配对
    /// 同一 CJK bigram transform（ADR-0007）。
    fn batch_upsert_fts_in_tx(
        tx: &rusqlite::Transaction<'_>,
        upserts: &[(StableId, Vec<u8>, String)],
    ) -> PortResult<()> {
        if upserts.is_empty() {
            return Ok(());
        }
        let mut next_fts_rowid: Option<i64> = None;
        let mut allocate_rowid = || -> PortResult<i64> {
            match next_fts_rowid {
                Some(id) => {
                    next_fts_rowid = Some(id + 1);
                    Ok(id)
                }
                None => {
                    let max: i64 = tx
                        .query_row("SELECT COALESCE(MAX(rowid), 0) FROM fts", [], |row| {
                            row.get(0)
                        })
                        .map_err(backend)?;
                    next_fts_rowid = Some(max + 2);
                    Ok(max + 1)
                }
            }
        };
        for chunk in upserts.chunks(BULK_INSERT_ROWS_PER_CHUNK) {
            // StableId 无字符串反解构造器，故存其 serde JSON 以便查询时无损重建
            // （wire 串不含 stability，无法从 as_str() 还原完整身份）。
            let ids: Vec<&str> = chunk.iter().map(|(id, _, _)| id.as_str()).collect();
            let placeholders = in_placeholders(ids.len());
            tx.execute(
                &format!(
                    "DELETE FROM fts
                     WHERE rowid IN (
                         SELECT fts_rowid FROM fts_ids WHERE wire_id IN ({placeholders})
                     )"
                ),
                rusqlite::params_from_iter(ids.iter().copied()),
            )
            .map_err(backend)?;
            tx.execute(
                &format!("DELETE FROM fts_ids WHERE wire_id IN ({placeholders})"),
                rusqlite::params_from_iter(ids.iter().copied()),
            )
            .map_err(backend)?;

            // 显式 rowid 的顺序与消息实体顺序一一对应；非 Message 边车行 rowid 为 NULL。
            // 先收集自有行（id_json/wire 是逐实体新建的 String，不能跨语句借用），
            // 再在 execute 语句内取引用构造参数。
            let mut fts_rows: Vec<(i64, String, String)> = Vec::new();
            let mut fts_ids_rows: Vec<(String, String, Option<i64>)> = Vec::new();
            for (id, _payload, text) in chunk {
                let id_json = serde_json::to_string(id).map_err(backend)?;
                if id.kind() == IdKind::Message {
                    let fts_rowid = allocate_rowid()?;
                    fts_rows.push((fts_rowid, id_json.clone(), bigram_cjk(text)));
                    fts_ids_rows.push((id.as_str().to_string(), id_json, Some(fts_rowid)));
                } else {
                    fts_ids_rows.push((id.as_str().to_string(), id_json, None));
                }
            }
            if !fts_rows.is_empty() {
                const _: () = assert!(3 * BULK_INSERT_ROWS_PER_CHUNK <= 950);
                let sql = format!(
                    "INSERT INTO fts(rowid, id, text) VALUES {}",
                    multi_row_values(fts_rows.len(), 3)
                );
                let params: Vec<&dyn rusqlite::ToSql> = fts_rows
                    .iter()
                    .flat_map(|(rowid, id_json, text)| {
                        let c0: &dyn rusqlite::ToSql = rowid;
                        let c1: &dyn rusqlite::ToSql = id_json;
                        let c2: &dyn rusqlite::ToSql = text;
                        [c0, c1, c2]
                    })
                    .collect();
                tx.execute(&sql, rusqlite::params_from_iter(params))
                    .map_err(backend)?;
            }
            const _: () = assert!(3 * BULK_INSERT_ROWS_PER_CHUNK <= 950);
            let sql = format!(
                "INSERT INTO fts_ids(wire_id, id_json, fts_rowid) VALUES {}",
                multi_row_values(fts_ids_rows.len(), 3)
            );
            let params: Vec<&dyn rusqlite::ToSql> = fts_ids_rows
                .iter()
                .flat_map(|(wire, id_json, rowid)| {
                    let c0: &dyn rusqlite::ToSql = wire;
                    let c1: &dyn rusqlite::ToSql = id_json;
                    let c2: &dyn rusqlite::ToSql = rowid;
                    [c0, c1, c2]
                })
                .collect();
            tx.execute(&sql, rusqlite::params_from_iter(params))
                .map_err(backend)?;
        }
        Ok(())
    }

    /// 在给定事务内维护单条实体的 fts 行与 fts_ids 身份边车。
    ///
    /// 与批量提交路径同语义：先按边车记录的 rowid 删除旧 fts 行（避免内容列整表
    /// 扫描），再按 kind 门控——只有 Message 实体进入 fts 全文表，session/document
    /// 是容器实体，索引其正文会让搜索命中重复计数；非 Message 只保留身份边车
    /// （fts_rowid 为 NULL，按 NULL 定位删除即无操作）。
    /// 单条 `SearchIndex::index` 与 `CatalogStore::put` 共用（后者投影自 payload）。
    fn upsert_fts_row_in_tx(
        tx: &rusqlite::Transaction<'_>,
        id: &StableId,
        text: &str,
    ) -> PortResult<()> {
        // StableId 无字符串反解构造器，故存其 serde JSON 以便查询时无损重建
        // （wire 串不含 stability，无法从 as_str() 还原完整身份）。
        let id_json = serde_json::to_string(id).map_err(backend)?;
        tx.execute(
            "DELETE FROM fts
             WHERE rowid = (SELECT fts_rowid FROM fts_ids WHERE wire_id = ?1)",
            [id.as_str()],
        )
        .map_err(backend)?;
        tx.execute("DELETE FROM fts_ids WHERE wire_id = ?1", [id.as_str()])
            .map_err(backend)?;
        let fts_rowid = if id.kind() == IdKind::Message {
            // 索引侧 CJK bigram（ADR-0007）：`SearchIndex::index` 与
            // `CatalogStore::put` 两条单条写入路径与批量提交共用同一 transform。
            tx.execute(
                "INSERT INTO fts(id, text) VALUES(?1, ?2)",
                rusqlite::params![id_json, bigram_cjk(text)],
            )
            .map_err(backend)?;
            Some(tx.last_insert_rowid())
        } else {
            None
        };
        tx.execute(
            "INSERT INTO fts_ids(wire_id, id_json, fts_rowid) VALUES(?1, ?2, ?3)",
            rusqlite::params![id.as_str(), id_json, fts_rowid],
        )
        .map_err(backend)?;
        Ok(())
    }

    /// 在事务内把活动 generation 推进 1（单条 put/index 写入用）。
    ///
    /// 与批量路径（durable outbox 的 `base+1`）共用同一"内容变更即失效旧游标"
    /// 语义；单条路径无 CAS 前置（无并发写者场景），`active_generation + 1`
    /// 保证单调递增即可。
    fn advance_generation_in_tx(tx: &rusqlite::Transaction<'_>) -> PortResult<()> {
        tx.execute(
            "UPDATE store_metadata SET active_generation = active_generation + 1
             WHERE singleton = 1",
            [],
        )
        .map_err(backend)?;
        Ok(())
    }

    /// 从权威 catalog 全量重投影 FTS 索引，通过 durable outbox + generation 保证
    /// 重建期崩溃不污染当前活动 generation。
    ///
    /// catalog 是内容的权威事实源，`fts` 搜索索引是可重建的派生投影（ADR-0001）。本方法：
    /// 1. 以 catalog 为权威实体集，读取全部 `(id, payload)`，用 [`searchable_text`] 投影检索正文；
    ///    实体身份优先取 `fts_ids.id_json`（保真 kind+stability），缺失时回退 `from_wire`；
    /// 2. 先持久化一条 `building` intent，记录本次将索引的完整 id 集合与 digest；
    /// 3. 在单事务内**整表清空** `fts`/`fts_ids` 后按 catalog 集合重新写入，推进 generation，
    ///    并把 intent 标记 `activated`。
    ///
    /// 整表清空（而非逐条 upsert）是刻意的：rebuild 的场景正是“搜索索引已漂移/损坏”，
    /// 需清除任何不在 catalog 中的孤儿 `fts`/`fts_ids` 行。若事务中途失败，整个重建回滚，旧
    /// generation 及其索引原样保留，search 仍可用旧投影（“失败不污染旧 generation”）。
    ///
    /// 身份保真取 `fts_ids` 而非纯从 catalog wire 串还原：wire 串不含 stability，
    /// `from_wire` 只能得到 `Unstable`，会让 rebuild 后的搜索结果丢失原 Native/Reconstructed
    /// 身份（见 `SearchIndex::query` 存 id_json 的原因）。catalog 权威决定“有哪些实体、正文是什么”，
    /// `fts_ids` 保真“每个实体的完整身份”。
    ///
    /// rebuild 是显式维护命令，即使内容与现有投影一致也照常推进 generation——操作者
    /// 主动请求“干净重建”，不做 no-op 短路。返回重新索引的实体条数。
    pub fn rebuild_index(&self) -> PortResult<usize> {
        // 1) 以 catalog 为权威实体集，投影检索正文；身份优先取 fts_ids 保真。
        // 单个 LEFT JOIN 取代逐行 fts_ids 查询(每行一次 prepare+execute 的 N+1)。
        let upserts: Vec<(StableId, Vec<u8>, String)> = {
            let conn = self.conn.borrow();
            let mut stmt = conn
                .prepare(
                    "SELECT catalog.id, catalog.payload, fts_ids.id_json
                     FROM catalog
                     LEFT JOIN fts_ids ON fts_ids.wire_id = catalog.id
                     ORDER BY catalog.id ASC",
                )
                .map_err(backend)?;
            let rows = stmt
                .query_map([], |row| {
                    let wire: String = row.get(0)?;
                    let payload: Vec<u8> = row.get(1)?;
                    let id_json: Option<String> = row.get(2)?;
                    Ok((wire, payload, id_json))
                })
                .map_err(backend)?;
            let mut out = Vec::new();
            for row in rows {
                let (wire, payload, id_json) = row.map_err(backend)?;
                // 优先用 fts_ids 里保真的 id_json（含 kind+stability）；缺失才回退 from_wire。
                let id = match id_json {
                    Some(json) => serde_json::from_str(&json).map_err(backend)?,
                    None => StableId::from_wire(&wire).ok_or_else(|| {
                        PortError::Backend("catalog contains an invalid entity id".into())
                    })?,
                };
                let text = searchable_text(&payload);
                out.push((id, payload, text));
            }
            out
        };

        // 2) durable intent：记录本次重建将索引的完整集合（崩溃后 recover 会 abort 它）。
        let pending = self.begin_index_batch(&upserts, &[])?;

        // 3) 单事务：校验句柄 → 整表清空 FTS → 按 catalog 重投影 → 推进 generation → 标记 activated。
        let mut conn = self.conn.borrow_mut();
        let tx = conn.transaction().map_err(backend)?;
        Self::verify_pending_in_tx(&tx, &pending, &upserts, &[], &RelationManifests::default())?;

        tx.execute("DELETE FROM fts", []).map_err(backend)?;
        tx.execute("DELETE FROM fts_ids", []).map_err(backend)?;
        // Session 元数据投影（schema v11）：全量重建 `session_fts`——与消息
        // FTS 同一"catalog + claims 可重建投影"不变量，从声明与目录逐会话
        // 重投影，绝不从既有 session_fts 内容复制。
        Self::rebuild_all_session_search_in_tx(&tx)?;
        // 与提交路径一致：只有 Message 实体重投影进 fts，且把 fts5 行 rowid 回写
        // 进 fts_ids 边车，删除才能按 rowid 定位（见 ensure_fts_ids_rowid）。
        // 批量多行写入（与提交路径共用 batch_upsert_fts_in_tx；整表清空后
        // rowid 从 1 起显式分配，语义与逐行 last_insert_rowid 一致）。
        Self::batch_upsert_fts_in_tx(&tx, &upserts)?;

        tx.execute(
            "UPDATE store_metadata SET active_generation = ?1 WHERE singleton = 1",
            [pending.target_generation as i64],
        )
        .map_err(backend)?;
        tx.execute(
            "UPDATE index_batches
             SET state = 'activated', durable_point = 'activated', committed_at_ms = ?2
             WHERE operation_id = ?1",
            rusqlite::params![pending.operation_id, unix_ms()?],
        )
        .map_err(backend)?;

        tx.commit().map_err(backend)?;
        Ok(upserts.len())
    }

    /// 崩溃恢复：把所有停在 `building` 的 outbox 行标记为 `aborted`。
    ///
    /// FTS5 单存储下 `building` 行必然无已提交副作用（apply 与 activate 同事务，
    /// 要么全成要么全滚），故恢复动作是幂等的纯 journal 清理，不触碰 catalog/FTS。
    /// 返回被 abort 的批次数，供诊断输出。写路径打开时自动调用。
    pub fn recover_interrupted(&self) -> PortResult<usize> {
        let conn = self.conn.borrow();
        let n = conn
            .execute(
                "UPDATE index_batches
                 SET state = 'aborted', error_code = 'interrupted_before_activation'
                 WHERE state = 'building'",
                [],
            )
            .map_err(backend)?;
        Ok(n)
    }

    /// 只读统计停在 `building` 的 outbox 行数——中断恢复的"待收敛"证据。
    ///
    /// 与 [`recover_interrupted`](Self::recover_interrupted) 不同，本方法不改状态：
    /// 供 doctor 等只读路径观测“有多少无副作用 intent 尚待下次写打开收敛”，
    /// 作为 durable outbox 中断恢复与 generation 一致性的证据。
    pub fn interrupted_batch_count(&self) -> PortResult<u64> {
        let conn = self.conn.borrow();
        let n: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM index_batches WHERE state = 'building'",
                [],
                |row| row.get(0),
            )
            .map_err(backend)?;
        u64::try_from(n).map_err(backend)
    }

    /// 读回一条 outbox 行（供测试与诊断）。
    pub fn index_batch(&self, operation_id: &str) -> PortResult<Option<IndexBatch>> {
        let conn = self.conn.borrow();
        let mut stmt = conn
            .prepare(
                "SELECT operation_id, base_generation, target_generation, state,
                        operation_digest, upsert_ids_json, delete_ids_json,
                        relation_upserts_json, relation_deletes_json,
                        source_replacements_json, durable_point, error_code
                 FROM index_batches WHERE operation_id = ?1",
            )
            .map_err(backend)?;
        let mut rows = stmt.query([operation_id]).map_err(backend)?;
        match rows.next().map_err(backend)? {
            None => Ok(None),
            Some(row) => {
                let upsert_json: String = row.get(5).map_err(backend)?;
                let delete_json: String = row.get(6).map_err(backend)?;
                let relation_upserts_json: String = row.get(7).map_err(backend)?;
                let relation_deletes_json: String = row.get(8).map_err(backend)?;
                let source_replacements_json: String = row.get(9).map_err(backend)?;
                Ok(Some(IndexBatch {
                    operation_id: row.get(0).map_err(backend)?,
                    base_generation: u64::try_from(row.get::<_, i64>(1).map_err(backend)?)
                        .map_err(backend)?,
                    target_generation: u64::try_from(row.get::<_, i64>(2).map_err(backend)?)
                        .map_err(backend)?,
                    state: row.get(3).map_err(backend)?,
                    operation_digest: row.get(4).map_err(backend)?,
                    upsert_ids: serde_json::from_str(&upsert_json).map_err(backend)?,
                    delete_ids: serde_json::from_str(&delete_json).map_err(backend)?,
                    relation_upserts: serde_json::from_str(&relation_upserts_json)
                        .map_err(backend)?,
                    relation_deletes: serde_json::from_str(&relation_deletes_json)
                        .map_err(backend)?,
                    source_replacements: serde_json::from_str(&source_replacements_json)
                        .map_err(backend)?,
                    durable_point: row.get(10).map_err(backend)?,
                    error_code: row.get(11).map_err(backend)?,
                }))
            }
        }
    }
}

/// Canonical relation projection version stored in `source_relation_scans`.
/// Resume-claim schema changes do not change relation completeness semantics.
const RELATION_SCHEMA_VERSION: i64 = 7;

/// 当前 catalog schema 版本。每次结构变更 +1 并在 [`SqliteStore::migrate`] 追加步骤。
///
/// v8：新增 `source_session_resume_claims`（ADR-0009）——source-scoped Resume
/// Metadata 声明的持久化表。
///
/// v9：`source_scans` 增加可空 `provider_id TEXT` 列——`sync --discover` 用它
/// 按 provider diff 已存源路径，找出已被删除的源并合成空批 tombstone。
/// 旧行保持 NULL（直到该源被再次扫描时回填）；列是 additive，v8 库前向迁移。
///
/// v10：`message_vec` 语义向量边车表（#3）。与 `fts` 同级的 catalog 投影，
/// 可从 catalog 全量重建；记录 model_id/dimension，换模型后旧向量可识别可清理。
///
/// v11：新增 `session_fts` 与 `session_fts_ids`，作为可重建、隐私安全的
/// Session metadata 搜索投影（resolved Provider-native Session ID、pair-observed
/// Original Working Directory、首个有效 user request 的 title-like 字段）；
/// 旧目录无需数据迁移，rebuild 或后续 source 提交填充。Provider custom
/// title/summary 仍未进入 Canonical 契约，继续显式 deferred。
///
/// v12：新增 `tool_activities` 与 `tool_activity_membership`——typed tool-call
/// 观察投影，content-addressed activity_id 跨 source 去重，生命周期镜像
/// `message_placements`（complete-scan replace、incomplete-scan union、
/// claims tombstone）；随 rebuild 或后续 source 提交填充。
pub const SCHEMA_VERSION: i64 = 12;

impl CatalogStore for SqliteStore {
    fn get(&self, id: &StableId) -> PortResult<Option<Vec<u8>>> {
        let conn = self.conn.borrow();
        let mut stmt = conn
            .prepare("SELECT payload FROM catalog WHERE id = ?1")
            .map_err(backend)?;
        let mut rows = stmt.query([id.as_str()]).map_err(backend)?;
        match rows.next().map_err(backend)? {
            Some(row) => Ok(Some(row.get::<_, Vec<u8>>(0).map_err(backend)?)),
            None => Ok(None),
        }
    }

    fn get_many(&self, ids: &[StableId]) -> PortResult<Vec<(StableId, Option<Vec<u8>>)>> {
        let conn = self.conn.borrow();
        let wires: Vec<&str> = ids.iter().map(|id| id.as_str()).collect();
        // 批量读取，分块在 SQLite 变量上限之下（复用 integrity check 的 chunk 模式），
        // 绝不逐条查询（N+1）。
        let mut payloads: BTreeMap<String, Vec<u8>> = BTreeMap::new();
        for chunk in chunk_ids(&wires) {
            let placeholders = chunk.iter().map(|_| "?").collect::<Vec<_>>().join(",");
            let mut stmt = conn
                .prepare(&format!(
                    "SELECT id, payload FROM catalog WHERE id IN ({placeholders})"
                ))
                .map_err(backend)?;
            let rows = stmt
                .query_map(rusqlite::params_from_iter(chunk.iter().copied()), |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?))
                })
                .map_err(backend)?;
            for row in rows {
                let (id, payload) = row.map_err(backend)?;
                payloads.insert(id, payload);
            }
        }
        // 保序：结果与 `ids` 同序；目录中不存在的 id → None。
        Ok(ids
            .iter()
            .map(|id| {
                let payload = payloads.get(id.as_str()).cloned();
                (id.clone(), payload)
            })
            .collect())
    }

    fn put(&self, id: &StableId, payload: &[u8]) -> PortResult<()> {
        let mut conn = self.conn.borrow_mut();
        let tx = conn.transaction().map_err(backend)?;
        tx.execute(
            "INSERT INTO catalog(id, payload) VALUES(?1, ?2)
             ON CONFLICT(id) DO UPDATE SET payload = excluded.payload",
            rusqlite::params![id.as_str(), payload],
        )
        .map_err(backend)?;
        // catalog 是内容的权威事实源：put 更新 payload 后必须同步维护 fts/边车，
        // 否则消息内容更新后旧文本仍可搜（与 rebuild_index 用同一 searchable_text
        // 投影函数，避免再次分叉）。
        Self::upsert_fts_row_in_tx(&tx, id, &searchable_text(payload))?;
        // 单条写入同样是 catalog 变更：推进 generation，使此前签发的 search/list
        // 游标（绑定旧 generation）在此变更后失效，维持"游标绑定 generation"的
        // CAS 契约（与 commit_batch/rebuild_index 的 generation 语义一致）。
        Self::advance_generation_in_tx(&tx)?;
        tx.commit().map_err(backend)?;
        Ok(())
    }

    fn list(&self, limit: usize) -> PortResult<Vec<CatalogEntry>> {
        Self::list_filtered(&self.conn, None, limit)
    }

    fn list_sessions(&self, limit: usize) -> PortResult<Vec<CatalogEntry>> {
        Self::list_filtered(&self.conn, Some(IdKind::Session), limit)
    }

    fn count(&self) -> PortResult<u64> {
        let conn = self.conn.borrow();
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM catalog", [], |row| row.get(0))
            .map_err(backend)?;
        u64::try_from(count).map_err(backend)
    }

    fn active_generation(&self) -> PortResult<u64> {
        SqliteStore::active_generation(self)
    }
}

impl ContextGraphStore for SqliteStore {
    fn load_session_graph(&self, session_id: &StableId) -> PortResult<SessionContextGraph> {
        if session_id.kind() != IdKind::Session {
            return Err(PortError::NotFound("session context not found".into()));
        }
        let conn = self.conn.borrow();
        let exists: bool = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM catalog WHERE id = ?1)",
                [session_id.as_str()],
                |row| row.get(0),
            )
            .map_err(backend)?;
        if !exists {
            return Err(PortError::NotFound("session context not found".into()));
        }

        let sources = Self::relation_sources_for_session(&conn, session_id.as_str())?;
        Self::require_relation_complete_sources(&conn, &sources, true, "session")?;
        let stored_session_id = Self::stable_id_from_store(&conn, session_id.as_str())?;

        let raw_placements = {
            let mut stmt = conn
                .prepare(
                    "SELECT placement_id, document_id, message_id, source_ordinal,
                            is_sidechain, byte_start, byte_end
                     FROM message_placements
                     WHERE session_id = ?1
                     ORDER BY document_id, source_ordinal, placement_id",
                )
                .map_err(backend)?;
            let rows = stmt
                .query_map([session_id.as_str()], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, i64>(4)?,
                        row.get::<_, Option<i64>>(5)?,
                        row.get::<_, Option<i64>>(6)?,
                    ))
                })
                .map_err(backend)?;
            let mut placements = Vec::new();
            for row in rows {
                placements.push(row.map_err(backend)?);
            }
            placements
        };

        let mut message_wires = BTreeSet::new();
        let mut document_wires = BTreeSet::new();

        // 先收集全部 wires，再批量加载 payload/identity（避免 N+1）。
        for (_, document_id, message_id, _, _, _, _) in &raw_placements {
            message_wires.insert(message_id.clone());
            document_wires.insert(document_id.clone());
        }
        {
            let mut stmt = conn
                .prepare(
                    "SELECT DISTINCT document_id
                     FROM source_membership
                     WHERE message_id = ?1 AND document_id IS NOT NULL",
                )
                .map_err(backend)?;
            let rows = stmt
                .query_map([session_id.as_str()], |row| row.get::<_, String>(0))
                .map_err(backend)?;
            for row in rows {
                document_wires.insert(row.map_err(backend)?);
            }
        }

        // 边查询提前到批量加载之前:父消息 wire 必须并入 fts_ids 身份批集,否则
        // 每条边一次身份查询(N+1),且孤儿父(在本会话无出现的父)会退化为
        // Unstable 身份(降级)。
        let raw_edges = {
            let mut stmt = conn
                .prepare(
                    "SELECT edges.child_placement_id, edges.parent_message_id,
                            edges.parent_native_id, edges.relation
                     FROM message_edges AS edges
                     JOIN message_placements AS placements
                       ON placements.placement_id = edges.child_placement_id
                     WHERE placements.session_id = ?1
                     ORDER BY edges.child_placement_id",
                )
                .map_err(backend)?;
            let rows = stmt
                .query_map([session_id.as_str()], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Option<String>>(2)?,
                        row.get::<_, String>(3)?,
                    ))
                })
                .map_err(backend)?;
            let mut edges = Vec::new();
            for row in rows {
                edges.push(row.map_err(backend)?);
            }
            edges
        };
        let mut parent_message_wires = BTreeSet::new();
        for (_, parent_message_id, _, _) in &raw_edges {
            parent_message_wires.insert(parent_message_id.clone());
        }

        // Batch-load message payloads and fts_ids identity for all wires at
        // once (was N+1 per message: one payload read + two identity reads).
        // Chunked under the SQLite variable limit for very large sessions.
        // 身份批集额外并入边的父消息 wire(含孤儿父),保真其 fts_ids 身份等级。
        let mut payload_by_id: BTreeMap<String, Vec<u8>> = BTreeMap::new();
        let mut id_json_by_wire: BTreeMap<String, String> = BTreeMap::new();
        let all_wires: Vec<&str> = message_wires
            .iter()
            .chain(document_wires.iter())
            .map(|wire| wire.as_str())
            .collect();
        let identity_wires: Vec<&str> = all_wires
            .iter()
            .copied()
            .chain(parent_message_wires.iter().map(|wire| wire.as_str()))
            .collect();
        for chunk in chunk_ids(&all_wires) {
            let placeholders = chunk.iter().map(|_| "?").collect::<Vec<_>>().join(",");
            let mut stmt = conn
                .prepare(&format!(
                    "SELECT id, payload FROM catalog WHERE id IN ({placeholders})"
                ))
                .map_err(backend)?;
            let rows = stmt
                .query_map(rusqlite::params_from_iter(chunk.iter().copied()), |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?))
                })
                .map_err(backend)?;
            for row in rows {
                let (id, payload) = row.map_err(backend)?;
                payload_by_id.insert(id, payload);
            }
        }
        for chunk in chunk_ids(&identity_wires) {
            let placeholders = chunk.iter().map(|_| "?").collect::<Vec<_>>().join(",");
            let mut stmt = conn
                .prepare(&format!(
                    "SELECT wire_id, id_json FROM fts_ids WHERE wire_id IN ({placeholders})"
                ))
                .map_err(backend)?;
            let rows = stmt
                .query_map(rusqlite::params_from_iter(chunk.iter().copied()), |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                })
                .map_err(backend)?;
            for row in rows {
                let (wire_id, id_json) = row.map_err(backend)?;
                id_json_by_wire.insert(wire_id, id_json);
            }
        }

        let mut placements = Vec::with_capacity(raw_placements.len());
        for (placement_id, document_id, message_id, ordinal, sidechain, start, end) in
            raw_placements
        {
            let span = match (start, end) {
                (None, None) => None,
                (Some(start), Some(end)) => Some(EvidenceSpan {
                    start: u64::try_from(start).map_err(backend)?,
                    end: u64::try_from(end).map_err(backend)?,
                }),
                _ => {
                    return Err(PortError::Backend(
                        "stored placement has a partial span".into(),
                    ));
                }
            };
            placements.push(MessagePlacement {
                id: PlacementId::from_wire(&placement_id).ok_or_else(|| {
                    PortError::Backend("stored placement has an invalid id".into())
                })?,
                session_id: stored_session_id.clone(),
                source_document_id: Self::stable_id_from_wire(&document_id, &id_json_by_wire)?,
                message_id: Self::stable_id_from_wire(&message_id, &id_json_by_wire)?,
                source_ordinal: u32::try_from(ordinal).map_err(backend)?,
                is_sidechain: sidechain != 0,
                span,
            });
        }

        let mut messages = Vec::with_capacity(message_wires.len());
        for wire in &message_wires {
            let payload = payload_by_id.get(wire).cloned().ok_or_else(|| {
                PortError::Backend("session placement references a missing message".into())
            })?;
            let map = match serde_json::from_slice::<serde_json::Value>(&payload) {
                Ok(serde_json::Value::Object(map)) => map,
                _ => {
                    return Err(PortError::Backend(
                        "stored message payload is not an object".into(),
                    ));
                }
            };
            let role = map
                .get("role")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| PortError::Backend("stored message is missing role".into()))
                .and_then(stored_role)?;
            let text = map
                .get("text")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| PortError::Backend("stored message is missing text".into()))?
                .to_string();
            let timestamp = match map.get("timestamp") {
                None | Some(serde_json::Value::Null) => None,
                Some(serde_json::Value::String(value)) => Some(value.clone()),
                Some(_) => {
                    return Err(PortError::Backend(
                        "stored message timestamp is not a string".into(),
                    ));
                }
            };
            messages.push(Message {
                id: Self::stable_id_from_wire(wire, &id_json_by_wire)?,
                role,
                text,
                timestamp,
            });
        }

        let mut source_documents = Vec::with_capacity(document_wires.len());
        for wire in &document_wires {
            let payload = payload_by_id.get(wire).cloned().ok_or_else(|| {
                PortError::Backend("session context references a missing document".into())
            })?;
            let map = match serde_json::from_slice::<serde_json::Value>(&payload) {
                Ok(serde_json::Value::Object(map)) => map,
                _ => {
                    return Err(PortError::Backend(
                        "stored document payload is not an object".into(),
                    ));
                }
            };
            source_documents.push(SourceDocument {
                id: Self::stable_id_from_wire(wire, &id_json_by_wire)?,
                provider_id: map
                    .get("provider")
                    .and_then(serde_json::Value::as_str)
                    .ok_or_else(|| {
                        PortError::Backend("stored document is missing provider".into())
                    })?
                    .to_string(),
                variant_id: map
                    .get("variant")
                    .and_then(serde_json::Value::as_str)
                    .ok_or_else(|| PortError::Backend("stored document is missing variant".into()))?
                    .to_string(),
                fingerprint: map
                    .get("fingerprint")
                    .and_then(serde_json::Value::as_str)
                    .ok_or_else(|| {
                        PortError::Backend("stored document is missing fingerprint".into())
                    })?
                    .to_string(),
                len: map
                    .get("len")
                    .and_then(serde_json::Value::as_u64)
                    .ok_or_else(|| {
                        PortError::Backend("stored document is missing byte length".into())
                    })?,
            });
        }

        let mut edges = Vec::with_capacity(raw_edges.len());
        for (child_placement_id, parent_message_id, parent_native_id, relation) in raw_edges {
            edges.push(MessageEdge {
                child_placement_id: PlacementId::from_wire(&child_placement_id).ok_or_else(
                    || PortError::Backend("stored edge has an invalid child placement id".into()),
                )?,
                parent_message_id: Self::stable_id_from_wire(&parent_message_id, &id_json_by_wire)?,
                parent_native_id,
                relation: stored_relation(&relation)?,
            });
        }

        let graph = SessionContextGraph {
            session_id: stored_session_id,
            messages,
            source_documents,
            placements,
            edges,
        };
        graph
            .validate()
            .map_err(|error| PortError::Backend(error.to_string()))?;
        Ok(graph)
    }

    fn message_contexts(&self, message_id: &StableId) -> PortResult<Vec<MessageContextCandidate>> {
        if message_id.kind() != IdKind::Message {
            return Err(PortError::NotFound("message context not found".into()));
        }
        let conn = self.conn.borrow();
        let exists: bool = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM catalog WHERE id = ?1)",
                [message_id.as_str()],
                |row| row.get(0),
            )
            .map_err(backend)?;
        if !exists {
            return Err(PortError::NotFound("message context not found".into()));
        }

        let message_sources = Self::relation_sources_for_message(&conn, message_id.as_str())?;
        Self::require_relation_complete_sources(&conn, &message_sources, false, "message")?;
        let mut grouped = BTreeMap::<String, Vec<PlacementId>>::new();
        {
            let mut stmt = conn
                .prepare(
                    "SELECT session_id, placement_id
                     FROM message_placements
                     WHERE message_id = ?1
                     ORDER BY session_id, placement_id",
                )
                .map_err(backend)?;
            let rows = stmt
                .query_map([message_id.as_str()], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                })
                .map_err(backend)?;
            for row in rows {
                let (session_id, placement_id) = row.map_err(backend)?;
                grouped.entry(session_id).or_default().push(
                    PlacementId::from_wire(&placement_id).ok_or_else(|| {
                        PortError::Backend("stored placement has an invalid id".into())
                    })?,
                );
            }
        }

        let mut candidates = Vec::with_capacity(grouped.len());
        for (session_wire, mut placement_ids) in grouped {
            let session_sources = Self::relation_sources_for_session(&conn, &session_wire)?;
            Self::require_relation_complete_sources(&conn, &session_sources, true, "session")?;
            placement_ids.sort();
            candidates.push(MessageContextCandidate {
                session_id: Self::stable_id_from_store(&conn, &session_wire)?,
                placement_ids,
            });
        }
        Ok(candidates)
    }

    fn session_of(
        &self,
        message_ids: &[StableId],
    ) -> PortResult<Vec<(StableId, Option<StableId>)>> {
        let conn = self.conn.borrow();
        let wires: Vec<&str> = message_ids.iter().map(|id| id.as_str()).collect();
        // 批量解析归属会话：每块一条 `MIN(session_id) GROUP BY message_id`，
        // 分块在 SQLite 变量上限之下（与 get_many 同一模式，无 N+1）。
        // MIN 取 wire id 字典序最小的会话（确定性，跨页稳定）。
        let mut owners: BTreeMap<String, String> = BTreeMap::new();
        for chunk in chunk_ids(&wires) {
            let placeholders = chunk.iter().map(|_| "?").collect::<Vec<_>>().join(",");
            let mut stmt = conn
                .prepare(&format!(
                    "SELECT message_id, MIN(session_id)
                     FROM message_placements
                     WHERE message_id IN ({placeholders})
                     GROUP BY message_id"
                ))
                .map_err(backend)?;
            let rows = stmt
                .query_map(rusqlite::params_from_iter(chunk.iter().copied()), |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                })
                .map_err(backend)?;
            for row in rows {
                let (message_id, session_id) = row.map_err(backend)?;
                owners.insert(message_id, session_id);
            }
        }
        // 保序：与 `message_ids` 同序；无任何 placement 的消息 → None。
        message_ids
            .iter()
            .map(|id| {
                let session = match owners.get(id.as_str()) {
                    Some(wire) => Some(StableId::from_wire(wire).ok_or_else(|| {
                        PortError::Backend("stored placement has an invalid session id".into())
                    })?),
                    None => None,
                };
                Ok((id.clone(), session))
            })
            .collect()
    }

    fn source_placements_of(
        &self,
        message_ids: &[StableId],
    ) -> PortResult<Vec<(StableId, Option<SourcePlacement>)>> {
        let conn = self.conn.borrow();
        let wires: Vec<&str> = message_ids.iter().map(|id| id.as_str()).collect();
        // 批量读取全部相关 placement，再在 Rust 侧取每个 message 的确定性单个
        // placement（source_document_id 字典序最小，其次 source_ordinal）——
        // 与 session_of 的 MIN 约定一致，跨调用稳定。无 N+1。
        let mut best: BTreeMap<String, (String, Option<i64>, Option<i64>)> = BTreeMap::new();
        for chunk in chunk_ids(&wires) {
            let placeholders = chunk.iter().map(|_| "?").collect::<Vec<_>>().join(",");
            let mut stmt = conn
                .prepare(&format!(
                    "SELECT message_id, document_id, byte_start, byte_end
                     FROM message_placements
                     WHERE message_id IN ({placeholders})
                     ORDER BY document_id, source_ordinal"
                ))
                .map_err(backend)?;
            let rows = stmt
                .query_map(rusqlite::params_from_iter(chunk.iter().copied()), |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Option<i64>>(2)?,
                        row.get::<_, Option<i64>>(3)?,
                    ))
                })
                .map_err(backend)?;
            for row in rows {
                let (message_id, document_id, byte_start, byte_end) = row.map_err(backend)?;
                // 已按 document_id, source_ordinal 排序 → 每 message 首条即确定性最小。
                best.entry(message_id)
                    .or_insert_with(|| (document_id, byte_start, byte_end));
            }
        }
        message_ids
            .iter()
            .map(|id| {
                let placement = match best.get(id.as_str()) {
                    Some((document_id, byte_start, byte_end)) => Some(SourcePlacement {
                        source_document_id: StableId::from_wire(document_id).ok_or_else(|| {
                            PortError::Backend("stored placement has an invalid document id".into())
                        })?,
                        byte_start: byte_start.map(|v| v as u64),
                        byte_end: byte_end.map(|v| v as u64),
                    }),
                    None => None,
                };
                Ok((id.clone(), placement))
            })
            .collect()
    }

    fn tool_activities_for_messages(
        &self,
        message_ids: &[StableId],
    ) -> PortResult<Vec<serde_json::Value>> {
        // Delegate to the inherent method so CLI/MCP and the trait path share one
        // SQL implementation.
        SqliteStore::tool_activities_for_messages(self, message_ids)
    }

    fn context_stats(&self) -> PortResult<ContextStats> {
        let conn = self.conn.borrow();
        let placements: i64 = conn
            .query_row("SELECT COUNT(*) FROM message_placements", [], |row| {
                row.get(0)
            })
            .map_err(backend)?;
        let source_placement_claims: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM source_placement_membership",
                [],
                |row| row.get(0),
            )
            .map_err(backend)?;
        Ok(ContextStats {
            placements: u64::try_from(placements).map_err(backend)?,
            source_placement_claims: u64::try_from(source_placement_claims).map_err(backend)?,
        })
    }
}

impl SqliteStore {
    /// 把 Session 元数据命中（`session_fts MATCH`）并进既有消息命中列表。
    ///
    /// 查询侧先做与消息路径同一的 CJK bigram 前置变换 + 字面量化；候选按
    /// `bm25(session_fts)` 排序后取前 `limit` 条。每条命中以"首个非系统
    /// 消息"作代表（保既有 SearchHit 形状，不臆造 id）；无非系统消息的
    /// Session（metadata-only）直接以 canonical Session 身份返回。已由匹配
    /// 非系统消息代表过的 Session 被排除（R3 去重），系统/developer 消息
    /// 单独命中不得压制 metadata-only Session。
    fn append_session_metadata_hits(
        conn: &Connection,
        safe_query: &str,
        filters: &agent_session_grep_ports::SearchFilters,
        message_wires: &[String],
        limit: usize,
        hits: &mut Vec<SearchHit>,
    ) -> PortResult<()> {
        if limit == 0 {
            return Ok(());
        }
        let mut sql = String::from(
            "SELECT
                 COALESCE(
                     (SELECT fi.id_json
                        FROM fts_ids fi
                      WHERE fi.wire_id = (
                          SELECT representative.message_id
                            FROM message_placements representative
                            JOIN catalog representative_message
                              ON representative_message.id = representative.message_id
                           WHERE representative.session_id = sfi.session_wire
                             AND COALESCE(
                                     CASE WHEN json_valid(representative_message.payload)
                                          THEN json_extract(
                                              representative_message.payload,
                                              '$.role'
                                          ) END,
                                     ''
                                 ) NOT IN ('system', 'developer')
                           ORDER BY representative.document_id,
                                    representative.source_ordinal,
                                    representative.placement_id
                           LIMIT 1
                      )),
                     (SELECT fi.id_json
                        FROM fts_ids fi
                       WHERE fi.wire_id = sfi.session_wire)
                 ),
                 (SELECT representative.message_id
                    FROM message_placements representative
                    JOIN catalog representative_message
                      ON representative_message.id = representative.message_id
                   WHERE representative.session_id = sfi.session_wire
                     AND COALESCE(
                             CASE WHEN json_valid(representative_message.payload)
                                  THEN json_extract(representative_message.payload, '$.role') END,
                             ''
                         ) NOT IN ('system', 'developer')
                   ORDER BY representative.document_id,
                            representative.source_ordinal,
                            representative.placement_id
                   LIMIT 1),
                 sfi.session_wire,
                 bm25(session_fts)
             FROM session_fts
             JOIN session_fts_ids sfi ON sfi.session_wire = session_fts.session_wire
             WHERE session_fts MATCH ?1",
        );
        let mut params: Vec<Box<dyn rusqlite::ToSql>> = vec![Box::new(safe_query.to_string())];
        for message_wire in message_wires {
            sql.push_str(
                " AND NOT EXISTS (
                SELECT 1 FROM message_placements excluded_placement
                JOIN catalog excluded_message
                  ON excluded_message.id = excluded_placement.message_id
                WHERE excluded_placement.session_id = sfi.session_wire
                  AND excluded_placement.message_id = ?
                  AND COALESCE(
                          CASE WHEN json_valid(excluded_message.payload)
                               THEN json_extract(excluded_message.payload, '$.role') END,
                          ''
                      ) NOT IN ('system', 'developer')
            )",
            );
            params.push(Box::new(message_wire.clone()));
        }
        if !filters.providers.is_empty() || filters.since.is_some() || filters.until.is_some() {
            sql.push_str(
                " AND EXISTS (
                     SELECT 1 FROM message_placements filtered_placement
                     JOIN catalog filtered_document
                       ON filtered_document.id = filtered_placement.document_id
                     JOIN catalog filtered_message
                       ON filtered_message.id = filtered_placement.message_id
                     WHERE filtered_placement.session_id = sfi.session_wire",
            );
            if !filters.providers.is_empty() {
                sql.push_str(
                    " AND CASE WHEN json_valid(filtered_document.payload)
                              THEN json_extract(filtered_document.payload, '$.provider') END IN (",
                );
                for (index, provider) in filters.providers.iter().enumerate() {
                    if index > 0 {
                        sql.push(',');
                    }
                    sql.push('?');
                    params.push(Box::new(provider.as_str()));
                }
                sql.push(')');
            }
            if let Some(since) = filters.since {
                sql.push_str(
                    " AND asg_instant_sort_key(CASE WHEN json_valid(filtered_message.payload)
                                                     THEN json_extract(filtered_message.payload, '$.timestamp') END) >= ?",
                );
                params.push(Box::new(since.sort_key().to_vec()));
            }
            if let Some(until) = filters.until {
                sql.push_str(
                    " AND asg_instant_sort_key(CASE WHEN json_valid(filtered_message.payload)
                                                     THEN json_extract(filtered_message.payload, '$.timestamp') END) < ?",
                );
                params.push(Box::new(until.sort_key().to_vec()));
            }
            sql.push(')');
        }
        sql.push_str(" ORDER BY bm25(session_fts), sfi.session_wire LIMIT ?");
        params.push(Box::new(limit as i64));

        let mut stmt = conn.prepare(&sql).map_err(backend)?;
        let params_ref: Vec<&dyn rusqlite::ToSql> =
            params.iter().map(std::convert::AsRef::as_ref).collect();
        let rows = stmt
            .query_map(&*params_ref, |row| {
                let id_json: Option<String> = row.get(0)?;
                let message_wire: Option<String> = row.get(1)?;
                let session_wire: String = row.get(2)?;
                let bm25: f64 = row.get(3)?;
                Ok((id_json, message_wire, session_wire, bm25))
            })
            .map_err(backend)?;
        for row in rows {
            let (id_json, message_wire, session_wire, bm25) = row.map_err(backend)?;
            let id = match id_json {
                Some(json) => serde_json::from_str(&json).map_err(backend)?,
                None => message_wire
                    .as_deref()
                    .or(Some(session_wire.as_str()))
                    .and_then(StableId::from_wire)
                    .ok_or_else(|| {
                        PortError::Backend(
                            "session metadata representative has an invalid id".into(),
                        )
                    })?,
            };
            hits.push(SearchHit {
                id,
                score: -bm25 as f32,
                session_id: Some(session_wire),
                text: None,
                why_matched: Vec::new(),
                suggested_next_commands: Vec::new(),
                occurrences: 1,
                resume_available: false,
            });
        }
        Ok(())
    }
}

impl SearchIndex for SqliteStore {
    fn index(&self, id: &StableId, text: &str) -> PortResult<()> {
        let mut conn = self.conn.borrow_mut();
        let tx = conn.transaction().map_err(backend)?;
        Self::upsert_fts_row_in_tx(&tx, id, text)?;
        // 索引写入也是内容变更：推进 generation，保持游标 CAS 契约。
        Self::advance_generation_in_tx(&tx)?;
        tx.commit().map_err(backend)?;
        Ok(())
    }

    fn query_filtered(&self, query: SearchQuery<'_>, limit: usize) -> PortResult<Vec<SearchHit>> {
        let conn = self.conn.borrow();
        // 查询侧先做与索引侧同一的 CJK bigram transform（ADR-0007），再字面量化：
        // bigram 输出里的单个空格就是词元分隔符，顺序敏感——先字面量化会把
        // bigram 输出的空格包进引号，变成整段 bigram 连写的短语，无法匹配。
        // cursor digest 绑定的是 Application 侧的原始用户查询，此处变换不影响。
        // 用户查询按字面量分词：冒号/点号/连字符等是 FTS5 语法保留字符，直接
        // MATCH 会泄漏 `fts5: syntax error near "."` 之类的底层报错（10 角色
        // 体验测试缺陷）。把每个词用引号包裹成短语查询，保留词内特殊字符的字面
        // 含义，同时保持原来的空格 AND 语义。
        let safe_query = safe_fts_query(&bigram_cjk(query.text));
        if safe_query.is_empty() {
            // 空查询（全标点/空白）无词可查：返回空而非让 FTS5 报语法错误。
            return Ok(Vec::new());
        }
        let filters = query.filters;
        if filters.is_empty() {
            // 无 filter：保持原有 SQL 形状逐字节不变，结果与排序与旧路径一致。
            let mut hits = {
                let mut stmt = conn
                    .prepare(
                        "SELECT id, bm25(fts) FROM fts WHERE fts MATCH ?1
                         ORDER BY bm25(fts), id LIMIT ?2",
                    )
                    .map_err(backend)?;
                let rows = stmt
                    .query_map(rusqlite::params![&safe_query, limit as i64], |row| {
                        let id_json: String = row.get(0)?;
                        let bm25: f64 = row.get(1)?;
                        Ok((id_json, bm25))
                    })
                    .map_err(backend)?;
                collect_hits(rows)?
            };
            let message_wires: Vec<String> =
                hits.iter().map(|hit| hit.id.as_str().to_string()).collect();
            Self::append_session_metadata_hits(
                &conn,
                &safe_query,
                filters,
                &message_wires,
                limit,
                &mut hits,
            )?;
            hits.sort_by(|left, right| {
                right
                    .score
                    .total_cmp(&left.score)
                    .then_with(|| left.id.as_str().cmp(right.id.as_str()))
            });
            hits.truncate(limit);
            return Ok(hits);
        }

        // Filtered path：谓词全部下推到同一条 prepared query，在 LIMIT 之前
        // 约束候选集（R：分页窗口只切已过滤的钉住排序，绝不先截页后过滤）。
        // FTS5 规定 MATCH 谓词里的表引用必须是表名本体（别名会报
        // "no such column"），故查询与 bm25 用裸表名，其余列引用走别名。
        //
        // provider 维度（OR）：任一 placement 的 source document payload
        // `provider` 命中规范化 id 集合。时间维度（AND，[since, until) 半开）：
        // 消息自身 catalog payload 的 `timestamp`（权威事实源，Codex 现代的
        // null 与任何无法解析的值经 asg_instant_sort_key → NULL 而被排除）。
        let mut sql = String::from(
            "SELECT f.id, bm25(fts) FROM fts AS f
             WHERE fts MATCH ?1",
        );
        let mut params: Vec<Box<dyn rusqlite::ToSql>> = vec![Box::new(safe_query.clone())];
        if !filters.providers.is_empty() {
            let mut clause = String::from(
                " AND EXISTS (
                     SELECT 1 FROM message_placements mp
                     JOIN catalog doc ON doc.id = mp.document_id
                     WHERE mp.message_id = (
                         SELECT wire_id FROM fts_ids WHERE id_json = f.id
                     )
                     AND json_extract(doc.payload, '$.provider') IN (",
            );
            for (index, provider) in filters.providers.iter().enumerate() {
                if index > 0 {
                    clause.push(',');
                }
                clause.push('?');
                params.push(Box::new(provider.as_str()));
            }
            clause.push_str("))");
            sql.push_str(&clause);
        }
        if filters.since.is_some() || filters.until.is_some() {
            sql.push_str(
                " AND EXISTS (
                     SELECT 1 FROM catalog msg
                     WHERE msg.id = (
                         SELECT wire_id FROM fts_ids WHERE id_json = f.id
                     )",
            );
            if let Some(since) = filters.since {
                sql.push_str(
                    " AND asg_instant_sort_key(json_extract(msg.payload, '$.timestamp')) >= ?",
                );
                params.push(Box::new(since.sort_key().to_vec()));
            }
            if let Some(until) = filters.until {
                sql.push_str(
                    " AND asg_instant_sort_key(json_extract(msg.payload, '$.timestamp')) < ?",
                );
                params.push(Box::new(until.sort_key().to_vec()));
            }
            sql.push(')');
        }
        sql.push_str(" ORDER BY bm25(fts), f.id LIMIT ?");
        params.push(Box::new(limit as i64));

        let (mut hits, safe_query) = {
            let mut stmt = conn.prepare(&sql).map_err(backend)?;
            let params_ref: Vec<&dyn rusqlite::ToSql> =
                params.iter().map(std::convert::AsRef::as_ref).collect();
            let rows = stmt
                .query_map(&*params_ref, |row| {
                    let id_json: String = row.get(0)?;
                    let bm25: f64 = row.get(1)?;
                    Ok((id_json, bm25))
                })
                .map_err(backend)?;
            (collect_hits(rows)?, safe_query)
        };
        let message_wires: Vec<String> =
            hits.iter().map(|hit| hit.id.as_str().to_string()).collect();
        Self::append_session_metadata_hits(
            &conn,
            &safe_query,
            filters,
            &message_wires,
            limit,
            &mut hits,
        )?;
        hits.sort_by(|left, right| {
            right
                .score
                .total_cmp(&left.score)
                .then_with(|| left.id.as_str().cmp(right.id.as_str()))
        });
        hits.truncate(limit);
        Ok(hits)
    }

    fn query_faceted(
        &self,
        query: SearchQuery<'_>,
        limit: usize,
        facets: &SearchFacets,
    ) -> PortResult<Vec<SearchHit>> {
        if facets.is_default() {
            return self.query_filtered(query, limit);
        }
        let conn = self.conn.borrow();
        let safe_query = safe_fts_query(&bigram_cjk(query.text));
        if safe_query.is_empty() {
            return Ok(Vec::new());
        }
        // 带 facet 的钉住排序查询：与 query_filtered 同基座（filter 谓词全部下推），
        // 再叠加索引列上的 EXISTS 探针。每个谓词都走索引（fts_ids.id_json UNIQUE +
        // message_placements_message / tool_activities_message 等），无全表扫描；
        // kind/name 只用等值比较。sidechain 语义（确定性）：MainOnly = 无任何
        // sidechain placement；SubagentOnly = 至少一个 sidechain placement。
        let mut sql = String::from(
            "SELECT f.id, bm25(fts) FROM fts AS f
             WHERE fts MATCH ?1",
        );
        let mut params: Vec<Box<dyn rusqlite::ToSql>> = vec![Box::new(safe_query)];
        if !query.filters.providers.is_empty() {
            let mut clause = String::from(
                " AND EXISTS (
                     SELECT 1 FROM message_placements mp
                     JOIN catalog doc ON doc.id = mp.document_id
                     WHERE mp.message_id = (
                         SELECT wire_id FROM fts_ids WHERE id_json = f.id
                     )
                     AND json_extract(doc.payload, '$.provider') IN (",
            );
            for (index, provider) in query.filters.providers.iter().enumerate() {
                if index > 0 {
                    clause.push(',');
                }
                clause.push('?');
                params.push(Box::new(provider.as_str()));
            }
            clause.push_str("))");
            sql.push_str(&clause);
        }
        if query.filters.since.is_some() || query.filters.until.is_some() {
            sql.push_str(
                " AND EXISTS (
                     SELECT 1 FROM catalog msg
                     WHERE msg.id = (
                         SELECT wire_id FROM fts_ids WHERE id_json = f.id
                     )",
            );
            if let Some(since) = query.filters.since {
                sql.push_str(
                    " AND asg_instant_sort_key(json_extract(msg.payload, '$.timestamp')) >= ?",
                );
                params.push(Box::new(since.sort_key().to_vec()));
            }
            if let Some(until) = query.filters.until {
                sql.push_str(
                    " AND asg_instant_sort_key(json_extract(msg.payload, '$.timestamp')) < ?",
                );
                params.push(Box::new(until.sort_key().to_vec()));
            }
            sql.push(')');
        }
        match facets.sidechain {
            SidechainFacet::Include => {}
            SidechainFacet::MainOnly => {
                sql.push_str(
                    " AND NOT EXISTS(
                         SELECT 1 FROM fts_ids fi2
                         JOIN message_placements mp ON mp.message_id = fi2.wire_id
                         WHERE fi2.id_json = f.id AND mp.is_sidechain = 1
                     )",
                );
            }
            SidechainFacet::SubagentOnly => {
                sql.push_str(
                    " AND EXISTS(
                         SELECT 1 FROM fts_ids fi2
                         JOIN message_placements mp ON mp.message_id = fi2.wire_id
                         WHERE fi2.id_json = f.id AND mp.is_sidechain = 1
                     )",
                );
            }
        }
        if let Some(kind) = &facets.tool_kind {
            params.push(Box::new(kind.clone()));
            let index = params.len();
            sql.push_str(&format!(
                " AND EXISTS(
                     SELECT 1 FROM fts_ids fi2
                     JOIN tool_activities ta ON ta.message_id = fi2.wire_id
                     WHERE fi2.id_json = f.id AND ta.kind = ?{index}
                 )",
            ));
        }
        if let Some(name) = &facets.tool_name {
            params.push(Box::new(name.clone()));
            let index = params.len();
            sql.push_str(&format!(
                " AND EXISTS(
                     SELECT 1 FROM fts_ids fi2
                     JOIN tool_activities ta ON ta.message_id = fi2.wire_id
                     WHERE fi2.id_json = f.id AND ta.name = ?{index}
                 )",
            ));
        }
        sql.push_str(" ORDER BY bm25(fts), f.id LIMIT ?");
        params.push(Box::new(limit as i64));

        let mut stmt = conn.prepare(&sql).map_err(backend)?;
        let params_ref: Vec<&dyn rusqlite::ToSql> =
            params.iter().map(std::convert::AsRef::as_ref).collect();
        let rows = stmt
            .query_map(&*params_ref, |row| {
                let id_json: String = row.get(0)?;
                let bm25: f64 = row.get(1)?;
                Ok((id_json, bm25))
            })
            .map_err(backend)?;
        collect_hits(rows)
    }
}

/// 语义向量边车（#3，schema v10）。
///
/// 向量以 little-endian f32 blob 存储；余弦相似度在 Rust 侧计算——SQLite 无
/// 向量扩展依赖（sqlite-vec 需额外二进制），语料规模下全表扫描 + Rust 点积
/// 已足够，且不引入新供应链。查询按 `model_id` 过滤：换模型后旧维度向量不会
/// 与新向量混算出垃圾相似度。
///
/// `is_ready` 表示"这张表里有当前模型的向量"，而不是"表存在"——空表意味着
/// 语义检索不可用，Application 必须显式降级到 lexical_fallback。
impl SemanticIndex for SqliteStore {
    fn index_embedding(&self, id: &StableId, embedding: &[f32]) -> PortResult<()> {
        if embedding.is_empty() {
            return Err(PortError::Backend("embedding must not be empty".into()));
        }
        let model_id = self.semantic_model_id.borrow().clone().ok_or_else(|| {
            PortError::Backend("semantic model id not set; call set_semantic_model first".into())
        })?;
        let blob = f32_slice_to_bytes(embedding);
        let conn = self.conn.borrow();
        conn.execute(
            "INSERT INTO message_vec(wire_id, model_id, dimension, embedding)
             VALUES(?1, ?2, ?3, ?4)
             ON CONFLICT(wire_id) DO UPDATE SET
                 model_id = excluded.model_id,
                 dimension = excluded.dimension,
                 embedding = excluded.embedding",
            rusqlite::params![id.as_str(), model_id, embedding.len() as i64, blob],
        )
        .map_err(backend)?;
        Ok(())
    }

    fn query_semantic(&self, query_embedding: &[f32], limit: usize) -> PortResult<Vec<SearchHit>> {
        if query_embedding.is_empty() || limit == 0 {
            return Ok(Vec::new());
        }
        let Some(model_id) = self.semantic_model_id.borrow().clone() else {
            return Ok(Vec::new());
        };
        let conn = self.conn.borrow();
        // 只取与查询同模型同维度的向量：维度不符的行是换模型残留，跳过而非
        // 截断比较（截断会产出看似合理却无意义的相似度）。
        let mut stmt = conn
            .prepare(
                "SELECT mv.wire_id, fi.id_json, mv.embedding
                 FROM message_vec mv
                 LEFT JOIN fts_ids fi ON fi.wire_id = mv.wire_id
                 WHERE mv.model_id = ?1 AND mv.dimension = ?2",
            )
            .map_err(backend)?;
        let rows = stmt
            .query_map(
                rusqlite::params![model_id, query_embedding.len() as i64],
                |row| {
                    let wire: String = row.get(0)?;
                    let id_json: Option<String> = row.get(1)?;
                    let blob: Vec<u8> = row.get(2)?;
                    Ok((wire, id_json, blob))
                },
            )
            .map_err(backend)?;

        let mut scored: Vec<(f32, StableId)> = Vec::new();
        for row in rows {
            let (wire, id_json, blob) = row.map_err(backend)?;
            let vector = bytes_to_f32_vec(&blob);
            if vector.len() != query_embedding.len() {
                continue;
            }
            let score = cosine_similarity(query_embedding, &vector);
            // 身份优先取 fts_ids 的保真 id_json（含 kind+stability）；缺失回退
            // wire（降级为 Unstable，与 rebuild 同一约定）。
            let id = match id_json {
                Some(json) => serde_json::from_str(&json).map_err(backend)?,
                None => match StableId::from_wire(&wire) {
                    Some(id) => id,
                    None => continue,
                },
            };
            scored.push((score, id));
        }
        // 相似度降序；同分按 wire id 升序，保证分页顺序确定（与 FTS 路径的
        // bm25+id tiebreak 同一约定）。
        scored.sort_by(|a, b| {
            b.0.partial_cmp(&a.0)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.1.as_str().cmp(b.1.as_str()))
        });
        scored.truncate(limit);
        Ok(scored
            .into_iter()
            .map(|(score, id)| SearchHit {
                id,
                score,
                session_id: None,
                text: None,
                why_matched: Vec::new(),
                suggested_next_commands: Vec::new(),
                occurrences: 1,
                resume_available: false,
            })
            .collect())
    }

    fn is_ready(&self) -> bool {
        let Some(model_id) = self.semantic_model_id.borrow().clone() else {
            return false;
        };
        let conn = self.conn.borrow();
        conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM message_vec WHERE model_id = ?1)",
            [model_id],
            |row| row.get::<_, i64>(0),
        )
        .map(|exists| exists == 1)
        .unwrap_or(false)
    }
}

/// Serialize an f32 slice as little-endian bytes for BLOB storage.
fn f32_slice_to_bytes(values: &[f32]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(values.len() * 4);
    for value in values {
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    bytes
}

/// Read a little-endian f32 BLOB back into a vector. A trailing partial float
/// is dropped rather than reconstructed from padding.
fn bytes_to_f32_vec(bytes: &[u8]) -> Vec<f32> {
    bytes
        .chunks_exact(4)
        .map(|chunk| f32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
        .collect()
}

/// Cosine similarity of two equal-length vectors. Zero-norm inputs score 0
/// (no direction to compare) rather than producing NaN.
fn cosine_similarity(a: &[f32], b: &[f32]) -> f32 {
    let mut dot = 0.0f32;
    let mut norm_a = 0.0f32;
    let mut norm_b = 0.0f32;
    for (x, y) in a.iter().zip(b.iter()) {
        dot += x * y;
        norm_a += x * x;
        norm_b += y * y;
    }
    if norm_a == 0.0 || norm_b == 0.0 {
        return 0.0;
    }
    dot / (norm_a.sqrt() * norm_b.sqrt())
}

impl ResumeClaimsStore for SqliteStore {
    /// 批量解析 Session 的 Resume Metadata（ADR-0009）：分块 IN 一次查询
    /// 拿回全部命中 session 的声明行（无 N+1），仅在全部 source 声明完全
    /// 一致时解析；任一冲突都 fail closed。输出与 `session_ids` 同序。无声明/
    /// legacy → 全字段 None + `resume_available:false` + 明确的
    /// unavailable_reason——历史恒可检索，只是不可恢复。
    fn resume_of(&self, session_ids: &[StableId]) -> PortResult<Vec<SessionResumeMetadata>> {
        let conn = self.conn.borrow();
        let wires: Vec<&str> = session_ids.iter().map(|id| id.as_str()).collect();
        let mut claims: BTreeMap<String, Result<StoredResumeClaim, ()>> = BTreeMap::new();
        for chunk in chunk_ids(&wires) {
            let placeholders = chunk.iter().map(|_| "?").collect::<Vec<_>>().join(",");
            let mut stmt = conn
                .prepare(&format!(
                    "SELECT source_path, session_id, provider_id, provider_session_id,
                            provider_session_id_state, original_working_directory,
                            original_working_directory_state, pair_observed
                     FROM source_session_resume_claims
                     WHERE session_id IN ({placeholders})
                     ORDER BY source_path, session_id"
                ))
                .map_err(backend)?;
            let rows = stmt
                .query_map(rusqlite::params_from_iter(chunk.iter().copied()), |row| {
                    Ok(StoredResumeClaim {
                        session_id: row.get(1)?,
                        provider_id: row.get(2)?,
                        provider_session_id: row.get(3)?,
                        provider_session_id_state: row.get(4)?,
                        original_working_directory: row.get(5)?,
                        original_working_directory_state: row.get(6)?,
                        pair_observed: row.get(7)?,
                    })
                })
                .map_err(backend)?;
            for row in rows {
                let claim = row.map_err(backend)?;
                match claims.entry(claim.session_id.clone()) {
                    std::collections::btree_map::Entry::Vacant(entry) => {
                        entry.insert(Ok(claim));
                    }
                    std::collections::btree_map::Entry::Occupied(mut entry) => {
                        if entry.get().as_ref().is_ok_and(|current| current == &claim) {
                            continue;
                        }
                        let _ = entry.insert(Err(()));
                    }
                }
            }
        }
        Ok(session_ids
            .iter()
            .map(|id| match claims.get(id.as_str()) {
                Some(Ok(claim)) => resume_metadata_from_claim(id, claim),
                Some(Err(())) => SessionResumeMetadata {
                    session_id: id.clone(),
                    provider_id: None,
                    resume_available: false,
                    provider_session_id: None,
                    original_working_directory: None,
                    unavailable_reason: Some("conflicting resume metadata claims".into()),
                },
                None => SessionResumeMetadata {
                    session_id: id.clone(),
                    provider_id: None,
                    resume_available: false,
                    provider_session_id: None,
                    original_working_directory: None,
                    unavailable_reason: Some("no resume metadata claims".into()),
                },
            })
            .collect())
    }
}

impl SqliteStore {
    /// 批量取每个 canonical Session 的最近活动日期（`YYYY-MM-DD`）。
    ///
    /// 日期来源是会话内全部消息 payload 的 `timestamp`（provider-native ISO-8601）
    /// 的词法最大值的前 10 个字符。词法比较对 Claude Code / Codex 的
    /// `YYYY-MM-DDT...` 时间戳等价于时间排序；无 timestamp 的消息不参与。
    /// Human 表格展示专用，不进入 Robot/MCP 协议。无 N+1：按
    /// [`BATCH_IN_CHUNK`] 分块 IN 查询。
    pub fn latest_activity_ymd_for_sessions(
        &self,
        session_ids: &[StableId],
    ) -> PortResult<std::collections::HashMap<String, String>> {
        let conn = self.conn.borrow();
        let wires: Vec<&str> = session_ids.iter().map(|id| id.as_str()).collect();
        let mut out: std::collections::HashMap<String, String> = std::collections::HashMap::new();
        for chunk in chunk_ids(&wires) {
            let placeholders = chunk.iter().map(|_| "?").collect::<Vec<_>>().join(",");
            let mut stmt = conn
                .prepare(&format!(
                    "SELECT mp.session_id,
                            MAX(json_extract(c.payload, '$.timestamp')) AS latest
                     FROM message_placements mp
                     JOIN catalog c ON c.id = mp.message_id
                     WHERE mp.session_id IN ({placeholders})
                       AND json_extract(c.payload, '$.timestamp') IS NOT NULL
                     GROUP BY mp.session_id"
                ))
                .map_err(backend)?;
            let rows = stmt
                .query_map(rusqlite::params_from_iter(chunk.iter().copied()), |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?))
                })
                .map_err(backend)?;
            for row in rows {
                let (session_id, latest) = row.map_err(backend)?;
                if let Some(timestamp) = latest
                    && let Some(ymd) = timestamp.get(..10)
                {
                    out.insert(session_id, ymd.to_string());
                }
            }
        }
        Ok(out)
    }
}
fn collect_hits<F>(rows: rusqlite::MappedRows<'_, F>) -> PortResult<Vec<SearchHit>>
where
    F: FnMut(&rusqlite::Row<'_>) -> rusqlite::Result<(String, f64)>,
{
    let mut hits = Vec::new();
    for r in rows {
        let (id_json, bm25) = r.map_err(backend)?;
        let id: StableId = serde_json::from_str(&id_json).map_err(backend)?;
        // 取负使"分数越高越相关"，符合 SearchHit.score 的直觉（后端相对值）。
        hits.push(SearchHit {
            id,
            score: -bm25 as f32,
            // 端口只提供 id+score；session_id/text/guidance 由 Application 装配
            // （批量 session_of + 批量取 payload）。
            session_id: None,
            text: None,
            why_matched: Vec::new(),
            suggested_next_commands: Vec::new(),
            occurrences: 1,
            resume_available: false,
        });
    }
    Ok(hits)
}

/// 把用户搜索词转成 FTS5 安全查询：按空白分词，每个词用双引号包裹成短语查询，
/// 引号内的 FTS 保留字符（`: . - ( ) { } [ ] "`）按字面量匹配。
///
/// 尾随的 `*` 保留在引号外（`work*` → `"work"*`）：FTS5 只有引号外的 `*` 才是
/// 前缀操作符，包进引号（`"work*"`）会被分词器当字面分隔符丢弃，前缀查询静默
/// 退化为精确词匹配。
///
/// 这样 `search "codebuddy mcp.json"` 或搜索 Windows 路径片段不会触发
/// `fts5: syntax error near "."` 之类的底层错误，`hp-z8` 也不会被解析成
/// `hp NOT z8`（连字符被引号字面量化，不再是 NOT 操作符）。
/// 纯空白/纯标点输入返回空串。
///
/// 参考 hstry `sanitize_fts_query`（MIT，hstry/crates/hstry-core/src/db.rs:3177）
/// 的逐 token 引号化 + 引号外前缀 `*` 模式；本项目保留 CJK bigram 前置变换
/// （ADR-0007）与全标点词跳过。
fn safe_fts_query(query: &str) -> String {
    let mut words: Vec<String> = Vec::new();
    for raw in query.split_whitespace() {
        let is_prefix = raw.ends_with('*');
        let stem = raw.trim_end_matches('*').replace('"', "\"\"");
        if stem.is_empty() {
            continue;
        }
        // 全标点无字母数字的词对 FTS 无意义，跳过以免生成空短语 `""`。
        if stem.chars().all(|c| !c.is_alphanumeric()) {
            continue;
        }
        if is_prefix {
            words.push(format!("\"{stem}\"*"));
        } else {
            words.push(format!("\"{stem}\""));
        }
    }
    words.join(" ")
}

#[cfg(test)]
mod filtered_query_tests {
    //! SQL-shape pin: the filtered path must keep predicates inside one
    //! prepared statement (pushdown before LIMIT), parameterize every filter
    //! value, and preserve the unfiltered SQL byte-for-byte for empty filters.
    use super::*;
    use crate::tests::{counted_statements, entity_entry, placement, sid, source_batch};
    use agent_session_grep_ports::{SearchFilters, SearchInstant, SearchProvider};

    fn instant(seconds: i64) -> SearchInstant {
        SearchInstant {
            unix_seconds: seconds,
            nanosecond: 0,
        }
    }

    fn search_filtered(store: &SqliteStore, text: &str, filters: &SearchFilters) -> Vec<String> {
        let hits = store
            .query_filtered(SearchQuery { text, filters }, 100)
            .unwrap();
        hits.into_iter()
            .map(|hit| hit.id.as_str().to_string())
            .collect()
    }

    #[test]
    fn asg_instant_sort_key_round_trips_and_orders() {
        let store = SqliteStore::open_in_memory().unwrap();
        let conn = store.conn.borrow();
        let key: Vec<u8> = conn
            .query_row(
                "SELECT asg_instant_sort_key('2026-07-28T00:00:00Z')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(key, instant(1_785_196_800).sort_key().to_vec());
        // Offset forms normalize to the identical UTC key.
        let offset_key: Vec<u8> = conn
            .query_row(
                "SELECT asg_instant_sort_key('2026-07-28T02:00:00+02:00')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(offset_key, key);
        // NULL / non-string / unparseable inputs yield NULL (no match), never an error.
        for input in [
            "SELECT asg_instant_sort_key(NULL)",
            "SELECT asg_instant_sort_key(42)",
            "SELECT asg_instant_sort_key('not-a-timestamp')",
            "SELECT asg_instant_sort_key('2026-07-28T00:00:00')",
        ] {
            let value: Option<Vec<u8>> = conn.query_row(input, [], |row| row.get(0)).unwrap();
            assert!(value.is_none(), "{input}");
        }
        // Byte order is instant order across a mixed set.
        let ordered: Vec<String> = {
            let mut stmt = conn
                .prepare(
                    "SELECT value FROM (
                         SELECT '2026-07-28T00:00:01Z' AS value
                         UNION ALL SELECT '2026-07-27T23:59:59Z'
                         UNION ALL SELECT '2026-07-28T00:00:00.5Z'
                     )
                     ORDER BY asg_instant_sort_key(value)",
                )
                .unwrap();
            stmt.query_map([], |row| row.get(0))
                .unwrap()
                .map(Result::unwrap)
                .collect()
        };
        assert_eq!(
            ordered,
            [
                "2026-07-27T23:59:59Z",
                "2026-07-28T00:00:00.5Z",
                "2026-07-28T00:00:01Z",
            ]
        );
    }

    /// Two providers × three timestamps sharing one FTS token.
    struct FilterFixture {
        store: SqliteStore,
        claude_early: StableId,
        claude_mid: StableId,
        codex_mid: StableId,
        codex_late: StableId,
        null_ts: StableId,
    }

    fn filter_fixture() -> FilterFixture {
        let store = SqliteStore::open_in_memory().unwrap();
        let session = sid(IdKind::Session, b"filter-session");
        let claude_doc = sid(IdKind::Document, b"filter-claude-doc");
        let codex_doc = sid(IdKind::Document, b"filter-codex-doc");
        let claude_early = sid(IdKind::Message, b"filter-claude-early");
        let claude_mid = sid(IdKind::Message, b"filter-claude-mid");
        let codex_mid = sid(IdKind::Message, b"filter-codex-mid");
        let codex_late = sid(IdKind::Message, b"filter-codex-late");
        let null_ts = sid(IdKind::Message, b"filter-null-ts");

        let message_entry = |id: &StableId, timestamp: Option<&str>| {
            let ts = match timestamp {
                Some(value) => serde_json::Value::String(value.to_string()),
                None => serde_json::Value::Null,
            };
            (
                id.clone(),
                serde_json::json!({
                    "role": "user",
                    "text": "shared-token body",
                    "timestamp": ts,
                    "parent": null,
                    "parent_native_id": null,
                    "is_sidechain": false,
                    "session": null,
                    "sessions": [],
                    "span": null,
                    "spans": [],
                })
                .to_string()
                .into_bytes(),
                "shared-token body".to_string(),
            )
        };
        let document_entry = |id: &StableId, provider: &str| {
            (
                id.clone(),
                serde_json::json!({
                    "provider": provider,
                    "variant": format!("{provider}/synthetic-v1"),
                    "page_ref": {
                        "source_fingerprint": null,
                        "document_ordinal": 0,
                        "first_line": 0,
                        "last_line": 0,
                        "byte_range": [0, 0],
                    },
                    "len": 128,
                })
                .to_string()
                .into_bytes(),
                String::new(),
            )
        };

        let early = "2026-07-01T00:00:00Z";
        let mid = "2026-07-28T00:00:00Z";
        let late = "2026-08-10T00:00:00Z";
        let entries = vec![
            entity_entry(&session),
            document_entry(&claude_doc, "claude-code"),
            document_entry(&codex_doc, "codex"),
            message_entry(&claude_early, Some(early)),
            message_entry(&claude_mid, Some(mid)),
            message_entry(&codex_mid, Some(mid)),
            message_entry(&codex_late, Some(late)),
            message_entry(&null_ts, None),
        ];
        let mut ordinal = 0_u32;
        let mut next = |document: &StableId, message: &StableId| {
            let placement = placement(&session, document, message, ordinal, false, Some((0, 4)));
            ordinal += 1;
            placement
        };
        let placements = vec![
            next(&claude_doc, &claude_early),
            next(&claude_doc, &claude_mid),
            next(&codex_doc, &codex_mid),
            next(&codex_doc, &codex_late),
            next(&codex_doc, &null_ts),
        ];
        let source = source_batch(
            "filter-fixture.jsonl",
            entries,
            placements,
            Vec::new(),
            true,
        );
        store
            .commit_source_batches_if_changed(std::slice::from_ref(&source))
            .unwrap();
        FilterFixture {
            store,
            claude_early,
            claude_mid,
            codex_mid,
            codex_late,
            null_ts,
        }
    }

    #[test]
    fn empty_filters_match_unfiltered_query_results() {
        let fixture = filter_fixture();
        let unfiltered: Vec<String> = fixture
            .store
            .query("shared-token", 100)
            .unwrap()
            .into_iter()
            .map(|hit| hit.id.as_str().to_string())
            .collect();
        let empty = search_filtered(&fixture.store, "shared-token", &SearchFilters::default());
        assert_eq!(empty, unfiltered);
        assert_eq!(empty.len(), 5);
    }

    #[test]
    fn provider_filter_matches_document_provider_or() {
        let fixture = filter_fixture();
        let claude_only = SearchFilters {
            providers: vec![SearchProvider::Claude],
            ..SearchFilters::default()
        };
        let mut hits = search_filtered(&fixture.store, "shared-token", &claude_only);
        hits.sort();
        let mut expected = vec![
            fixture.claude_early.as_str().to_string(),
            fixture.claude_mid.as_str().to_string(),
        ];
        expected.sort();
        assert_eq!(hits, expected);

        // Multi-provider OR: both providers, and the null-timestamp row is
        // still included when no time dimension constrains it.
        let both = SearchFilters {
            providers: vec![SearchProvider::Claude, SearchProvider::Codex],
            ..SearchFilters::default()
        };
        let hits = search_filtered(&fixture.store, "shared-token", &both);
        assert_eq!(hits.len(), 5);
        assert!(hits.contains(&fixture.null_ts.as_str().to_string()));
    }

    #[test]
    fn time_filter_is_half_open_since_inclusive_until_exclusive() {
        let fixture = filter_fixture();
        // [mid, late): the two mid rows are in, early and late are out; the
        // null timestamp never satisfies a time predicate.
        let window = SearchFilters {
            providers: Vec::new(),
            since: Some(instant(1_785_196_800)), // 2026-07-28T00:00:00Z
            until: Some(instant(1_786_320_000)), // 2026-08-10T00:00:00Z
        };
        let mut hits = search_filtered(&fixture.store, "shared-token", &window);
        hits.sort();
        let mut expected = vec![
            fixture.claude_mid.as_str().to_string(),
            fixture.codex_mid.as_str().to_string(),
        ];
        expected.sort();
        assert_eq!(hits, expected, "since inclusive, until exclusive");

        // since-only: mid and late in, early out.
        let since_only = SearchFilters {
            providers: Vec::new(),
            since: Some(instant(1_785_196_800)),
            until: None,
        };
        let hits = search_filtered(&fixture.store, "shared-token", &since_only);
        assert_eq!(hits.len(), 3);
        assert!(!hits.contains(&fixture.claude_early.as_str().to_string()));

        // until-only: early and mid in, late out.
        let until_only = SearchFilters {
            providers: Vec::new(),
            since: None,
            until: Some(instant(1_786_320_000)),
        };
        let hits = search_filtered(&fixture.store, "shared-token", &until_only);
        assert_eq!(hits.len(), 3);
        assert!(!hits.contains(&fixture.codex_late.as_str().to_string()));
    }

    #[test]
    fn provider_and_time_dimensions_are_anded() {
        let fixture = filter_fixture();
        let filters = SearchFilters {
            providers: vec![SearchProvider::Codex],
            since: Some(instant(1_785_196_800)),
            until: Some(instant(1_786_320_000)),
        };
        let hits = search_filtered(&fixture.store, "shared-token", &filters);
        assert_eq!(hits, vec![fixture.codex_mid.as_str().to_string()]);
    }

    #[test]
    fn zero_match_filters_return_clean_empty_page() {
        let fixture = filter_fixture();
        let no_provider_overlap = SearchFilters {
            providers: vec![SearchProvider::Claude],
            since: Some(instant(1_786_320_000)), // late window: codex only
            until: None,
        };
        assert!(search_filtered(&fixture.store, "shared-token", &no_provider_overlap).is_empty());
        let empty_window = SearchFilters {
            providers: Vec::new(),
            since: Some(instant(1_800_000_000)),
            until: Some(instant(1_800_100_000)),
        };
        assert!(search_filtered(&fixture.store, "shared-token", &empty_window).is_empty());
    }

    #[test]
    fn filtered_predicates_apply_before_limit_in_one_statement() {
        // Pushdown proof: with limit = 1 the filtered query must return the
        // codex row even though a claude row sorts earlier in bm25 order —
        // filtering happens inside the single statement, before LIMIT.
        let fixture = filter_fixture();
        let filters = SearchFilters {
            providers: vec![SearchProvider::Codex],
            ..SearchFilters::default()
        };
        let mut hits = Vec::new();
        let statements = counted_statements(&fixture.store, || {
            hits = fixture
                .store
                .query_filtered(
                    SearchQuery {
                        text: "shared-token",
                        filters: &filters,
                    },
                    1,
                )
                .unwrap();
        });
        assert_eq!(hits.len(), 1);
        let hit = hits[0].id.as_str().to_string();
        assert!(
            hit == fixture.codex_mid.as_str()
                || hit == fixture.codex_late.as_str()
                || hit == fixture.null_ts.as_str(),
            "limit must cut the already-filtered ordering, got {hit}"
        );
        assert!(
            !hits
                .iter()
                .any(|h| h.id.as_str() == fixture.claude_early.as_str()
                    || h.id.as_str() == fixture.claude_mid.as_str()),
            "claude rows must be excluded before LIMIT"
        );
        assert_eq!(
            statements, 2,
            "filtered message and session metadata candidates each use one prepared statement"
        );
    }

    #[test]
    fn filtered_query_preserves_score_order_and_scores() {
        let fixture = filter_fixture();
        let filters = SearchFilters {
            providers: vec![SearchProvider::Codex],
            ..SearchFilters::default()
        };
        let hits = fixture
            .store
            .query_filtered(
                SearchQuery {
                    text: "shared-token",
                    filters: &filters,
                },
                100,
            )
            .unwrap();
        assert_eq!(hits.len(), 3);
        for pair in hits.windows(2) {
            assert!(
                pair[0].score > pair[1].score
                    || (pair[0].score == pair[1].score
                        && pair[0].id.as_str() < pair[1].id.as_str()),
                "score desc + id asc pinned order broken"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_session_grep_domain::{
        EvidenceSpan, IdKind, MessageRelation, Stability, ToolActivity, ToolActivityActor,
        ToolActivityKind, ToolActivityStatus,
    };
    use agent_session_grep_ports::SearchFilters;

    type PlacementSnapshotRow = (
        String,
        String,
        String,
        String,
        i64,
        i64,
        Option<i64>,
        Option<i64>,
    );

    pub(crate) fn sid(kind: IdKind, fact: &[u8]) -> StableId {
        StableId::derive(kind, Stability::Reconstructed, &[fact])
    }

    #[test]
    fn semantic_index_is_not_ready_without_model_or_vectors() {
        let store = SqliteStore::open_in_memory().unwrap();
        // 未设模型：未就绪，查询空，写入报错（不写无归属向量）。
        assert!(!store.is_ready());
        assert!(store.query_semantic(&[0.1, 0.2], 5).unwrap().is_empty());
        assert!(
            store
                .index_embedding(&sid(IdKind::Message, b"m"), &[0.1])
                .is_err()
        );
        // 设了模型但表空：仍未就绪，Application 必须降级为 lexical_fallback。
        store.set_semantic_model("test-model");
        assert!(!store.is_ready());
    }

    #[test]
    fn semantic_index_round_trips_and_ranks_by_cosine() {
        let store = SqliteStore::open_in_memory().unwrap();
        store.set_semantic_model("test-model");
        let near = sid(IdKind::Message, b"near");
        let far = sid(IdKind::Message, b"far");
        // near 与查询同向；far 正交。
        store.index_embedding(&near, &[1.0, 0.0, 0.0]).unwrap();
        store.index_embedding(&far, &[0.0, 1.0, 0.0]).unwrap();
        assert!(store.is_ready());

        let hits = store.query_semantic(&[1.0, 0.0, 0.0], 10).unwrap();
        assert_eq!(hits.len(), 2);
        assert_eq!(hits[0].id.as_str(), near.as_str());
        assert!(hits[0].score > hits[1].score);
        assert!((hits[0].score - 1.0).abs() < 1e-5);
        assert!(hits[1].score.abs() < 1e-5);
    }

    #[test]
    fn semantic_query_skips_other_models_and_dimensions() {
        let store = SqliteStore::open_in_memory().unwrap();
        store.set_semantic_model("model-a");
        store
            .index_embedding(&sid(IdKind::Message, b"a"), &[1.0, 0.0])
            .unwrap();
        // 换模型：旧向量因 model_id 不匹配被排除，不参与相似度。
        store.set_semantic_model("model-b");
        assert!(!store.is_ready());
        assert!(store.query_semantic(&[1.0, 0.0], 10).unwrap().is_empty());
        // 同模型但维度不同的查询也不匹配（避免截断比较产出无意义分数）。
        store.set_semantic_model("model-a");
        assert!(
            store
                .query_semantic(&[1.0, 0.0, 0.0], 10)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn semantic_index_upserts_and_clear_removes_only_that_model() {
        let store = SqliteStore::open_in_memory().unwrap();
        let id = sid(IdKind::Message, b"m");
        store.set_semantic_model("model-a");
        store.index_embedding(&id, &[1.0, 0.0]).unwrap();
        // 同 id 重写是 upsert，不是第二行。
        store.index_embedding(&id, &[0.0, 1.0]).unwrap();
        let hits = store.query_semantic(&[0.0, 1.0], 10).unwrap();
        assert_eq!(hits.len(), 1);
        assert!((hits[0].score - 1.0).abs() < 1e-5);

        store.set_semantic_model("model-b");
        store
            .index_embedding(&sid(IdKind::Message, b"n"), &[1.0, 0.0])
            .unwrap();
        assert_eq!(store.clear_embeddings("model-a").unwrap(), 1);
        // model-b 的向量不受影响。
        assert!(store.is_ready());
    }

    #[test]
    fn f32_blob_round_trips_and_drops_partial_tail() {
        let values = [1.5f32, -2.25, 0.0];
        let bytes = f32_slice_to_bytes(&values);
        assert_eq!(bytes.len(), 12);
        assert_eq!(bytes_to_f32_vec(&bytes), values);
        // 截断的尾部字节不被当成一个 float 复原。
        assert_eq!(bytes_to_f32_vec(&bytes[..10]).len(), 2);
    }

    #[test]
    fn cosine_similarity_handles_zero_norm() {
        assert_eq!(cosine_similarity(&[0.0, 0.0], &[1.0, 1.0]), 0.0);
        assert_eq!(cosine_similarity(&[1.0, 1.0], &[0.0, 0.0]), 0.0);
        assert!((cosine_similarity(&[1.0, 0.0], &[-1.0, 0.0]) + 1.0).abs() < 1e-6);
    }

    #[test]
    fn schema_v10_creates_message_vec_table() {
        let store = SqliteStore::open_in_memory().unwrap();
        assert_eq!(store.schema_version().unwrap(), SCHEMA_VERSION);
        assert_eq!(SCHEMA_VERSION, 12);
        let conn = store.conn.borrow();
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='message_vec'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn safe_fts_query_treats_operators_and_special_chars_as_literal_tokens() {
        // R4.1（ADR-0003）：FTS 操作符与保留字符（AND/OR/NOT/NEAR/引号/冒号/
        // 点号/连字符/星号）全部按字面量 token 包裹——输出永不含裸操作符，
        // 因此不可能触发 FTS5 语法错误或把查询解释为布尔表达式。纯标点词
        // （`*`、`-`）对 FTS 无意义，跳过。
        let cases = [
            // (输入查询, safe_fts_query 输出)
            ("AND OR NOT", "\"AND\" \"OR\" \"NOT\""),
            ("and or not", "\"and\" \"or\" \"not\""),
            ("NEAR", "\"NEAR\""),
            ("mcp.json", "\"mcp.json\""),
            ("a:b x-y", "\"a:b\" \"x-y\""),
            ("\"phrase\"", "\"\"\"phrase\"\"\""),
            // 尾随 `*` 保留在引号外才是 FTS5 前缀操作符（hstry sanitize 模式）；
            // 包进引号会被分词器当字面分隔符丢弃，前缀查询静默退化。
            ("prefix*", "\"prefix\"*"),
            ("work*", "\"work\"*"),
            ("a* b", "\"a\"* \"b\""),
            ("a**", "\"a\"*"),
            ("*a", "\"*a\""),
            ("column: value", "\"column:\" \"value\""),
            ("*", ""),
            ("* - :", ""),
            ("a - b", "\"a\" \"b\""),
            ("hello  world", "\"hello\" \"world\""),
            ("", ""),
            ("   ", ""),
        ];
        for (input, expected) in cases {
            assert_eq!(safe_fts_query(input), expected, "safe_fts_query({input:?})");
        }
        // 任何输出都不是裸操作符开头：逐词断言无 FTS 语法关键字裸露。
        for input in [
            "AND", "OR", "NOT", "NEAR", "a AND b", "NOT x", "x OR y", "a NEAR b",
        ] {
            let safe = safe_fts_query(input);
            for word in safe.split(' ') {
                assert!(
                    word.starts_with('"'),
                    "词必须被引号包裹: {input:?} -> {safe:?} (word {word:?})"
                );
            }
        }
    }

    #[test]
    fn hyphenated_query_stays_literal_not_not_operator() {
        // 回归（hstry sanitize_fts_query 修复的同一 misparse 类）：FTS5 裸查询
        // `hp-z8` 被解析成 `hp NOT z8` 并报 `no such column: z8`。字面量化后
        // 连字符不再是 NOT 操作符，含 `hp-z8` 的正文必须命中而不是语法错误。
        let store = SqliteStore::open_in_memory().unwrap();
        let id = sid(IdKind::Message, b"hyphen-m1");
        store
            .index(&id, "fixed the hp-z8 backplane firmware")
            .unwrap();
        let hits = store.query("hp-z8", 10).unwrap();
        assert_eq!(hits.len(), 1, "hp-z8 must recall, not parse as NOT");
        assert_eq!(hits[0].id, id);
    }

    #[test]
    fn trailing_star_keeps_fts5_prefix_semantics() {
        // hstry 模式：`*` 保留在引号外才是 FTS5 前缀操作符（`"work"*` 命中
        // workstation）；包进引号（`"work*"`）会被分词器当字面分隔符丢弃，
        // 前缀查询静默退化为精确词。纯字母数字查询输出与之前逐字节一致。
        let store = SqliteStore::open_in_memory().unwrap();
        let id = sid(IdKind::Message, b"prefix-m1");
        store.index(&id, "the workstation was rebooted").unwrap();
        let hits = store.query("work*", 10).unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].id, id);
        // 精确词 `work` 不命中 workstation——证明 `*` 是前缀操作符而非字面量。
        assert!(store.query("work", 10).unwrap().is_empty());
    }

    fn sqlite_failure(code: i32) -> rusqlite::Error {
        rusqlite::Error::SqliteFailure(rusqlite::ffi::Error::new(code), None)
    }

    fn create_v6_schema(conn: &Connection) {
        conn.execute_batch(
            "CREATE TABLE catalog (id TEXT PRIMARY KEY, payload BLOB NOT NULL);
             CREATE VIRTUAL TABLE fts USING fts5(id UNINDEXED, text);
             CREATE TABLE store_metadata (
                 singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                 active_generation INTEGER NOT NULL
             );
             INSERT INTO store_metadata(singleton, active_generation) VALUES(1, 1);
             CREATE TABLE index_batches (
                 operation_id TEXT PRIMARY KEY,
                 base_generation INTEGER NOT NULL,
                 target_generation INTEGER NOT NULL,
                 state TEXT NOT NULL,
                 operation_digest TEXT NOT NULL,
                 upsert_ids_json TEXT NOT NULL,
                 delete_ids_json TEXT NOT NULL,
                 durable_point TEXT NOT NULL,
                 created_at_ms INTEGER NOT NULL,
                 committed_at_ms INTEGER,
                 error_code TEXT
             );
             CREATE INDEX index_batches_state ON index_batches(state);
             CREATE TABLE fts_ids (
                 wire_id TEXT PRIMARY KEY,
                 id_json TEXT NOT NULL UNIQUE
             );
             CREATE TABLE source_membership (
                 source_path TEXT NOT NULL,
                 message_id TEXT NOT NULL,
                 document_id TEXT,
                 PRIMARY KEY(source_path, message_id)
             );
             CREATE INDEX source_membership_source
             ON source_membership(source_path);
             CREATE TABLE source_scans (
                 source_path TEXT PRIMARY KEY,
                 scanned_at_ms INTEGER NOT NULL
             );
             PRAGMA user_version = 6;",
        )
        .unwrap();
    }

    #[test]
    fn sqlite_busy_maps_to_retryable_writer_busy() {
        let error = backend(sqlite_failure(rusqlite::ffi::SQLITE_BUSY));
        assert!(matches!(
            error,
            PortError::WriterBusy(message)
                if message == "SQLite storage is busy or locked by another writer"
        ));
    }

    #[test]
    fn sqlite_locked_maps_to_retryable_writer_busy() {
        let error = backend(sqlite_failure(rusqlite::ffi::SQLITE_LOCKED));
        assert!(matches!(
            error,
            PortError::WriterBusy(message)
                if message == "SQLite storage is busy or locked by another writer"
        ));
    }

    #[test]
    fn non_contention_sqlite_failure_remains_backend() {
        let error = backend(sqlite_failure(rusqlite::ffi::SQLITE_CORRUPT));
        assert!(matches!(error, PortError::Backend(_)));
    }

    type SourceState = (u64, Vec<(String, Vec<u8>)>, Vec<(String, String)>, String);

    fn source_state(store: &SqliteStore) -> SourceState {
        let conn = store.conn.borrow();
        let catalog = {
            let mut stmt = conn
                .prepare("SELECT id, payload FROM catalog ORDER BY id")
                .unwrap();
            let rows = stmt
                .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
                .unwrap();
            rows.map(Result::unwrap).collect()
        };
        let membership = {
            let mut stmt = conn
                .prepare(
                    "SELECT source_path, message_id FROM source_membership
                     ORDER BY source_path, message_id",
                )
                .unwrap();
            let rows = stmt
                .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
                .unwrap();
            rows.map(Result::unwrap).collect()
        };
        let digest = conn
            .query_row(
                "SELECT operation_digest FROM index_batches
                 WHERE state = 'activated' ORDER BY target_generation DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        (
            store.active_generation().unwrap(),
            catalog,
            membership,
            digest,
        )
    }

    pub(crate) fn entity_entry(id: &StableId) -> (StableId, Vec<u8>, String) {
        (
            id.clone(),
            format!("payload:{}", id.as_str()).into_bytes(),
            if id.kind() == IdKind::Message {
                format!("text:{}", id.as_str())
            } else {
                String::new()
            },
        )
    }

    fn relational_message_payload(
        session_id: &StableId,
        document_id: &StableId,
        parent_id: &StableId,
        parent_native_id: &str,
        is_sidechain: bool,
        span: (u64, u64),
    ) -> Vec<u8> {
        serde_json::json!({
            "role": "user",
            "text": "shared stable body",
            "timestamp": "2026-07-28T00:00:00Z",
            "parent": parent_id.as_str(),
            "parent_native_id": parent_native_id,
            "is_sidechain": is_sidechain,
            "session": session_id.as_str(),
            "sessions": [session_id.as_str()],
            "span": { "start": span.0, "end": span.1 },
            "spans": [{
                "document": document_id.as_str(),
                "start": span.0,
                "end": span.1,
            }],
        })
        .to_string()
        .into_bytes()
    }

    fn typed_message_entry(id: &StableId, text: &str) -> (StableId, Vec<u8>, String) {
        (
            id.clone(),
            serde_json::json!({
                "role": "user",
                "text": text,
                "timestamp": "2026-07-28T00:00:00Z",
                "parent": null,
                "parent_native_id": null,
                "is_sidechain": false,
                "session": null,
                "sessions": [],
                "span": null,
                "spans": [],
            })
            .to_string()
            .into_bytes(),
            text.to_string(),
        )
    }

    fn typed_document_entry(id: &StableId) -> (StableId, Vec<u8>, String) {
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

    pub(crate) fn placement(
        session_id: &StableId,
        document_id: &StableId,
        message_id: &StableId,
        source_ordinal: u32,
        is_sidechain: bool,
        span: Option<(u64, u64)>,
    ) -> MessagePlacement {
        MessagePlacement::new(
            session_id.clone(),
            document_id.clone(),
            message_id.clone(),
            source_ordinal,
            is_sidechain,
            span.map(|(start, end)| EvidenceSpan { start, end }),
        )
    }

    fn reply_edge(placement: &MessagePlacement, parent: &StableId) -> MessageEdge {
        MessageEdge {
            child_placement_id: placement.id.clone(),
            parent_message_id: parent.clone(),
            parent_native_id: Some("synthetic-parent".into()),
            relation: MessageRelation::Reply,
        }
    }

    pub(crate) fn source_batch(
        source_path: &str,
        entries: Vec<(StableId, Vec<u8>, String)>,
        placements: Vec<MessagePlacement>,
        edges: Vec<MessageEdge>,
        relation_complete: bool,
    ) -> SourceBatch {
        SourceBatch {
            source_path: source_path.into(),
            entries,
            placements,
            edges,
            activities: Vec::new(),
            relation_complete,
            len_bytes: None,
            fingerprint: None,
            provider_id: None,
            resume_claim: None,
        }
    }

    fn table_count(store: &SqliteStore, table: &str) -> i64 {
        store
            .conn
            .borrow()
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .unwrap()
    }

    fn source_placement_claims(store: &SqliteStore, source_path: &str) -> Vec<String> {
        let conn = store.conn.borrow();
        let mut stmt = conn
            .prepare(
                "SELECT placement_id FROM source_placement_membership
                 WHERE source_path = ?1 ORDER BY placement_id",
            )
            .unwrap();
        stmt.query_map([source_path], |row| row.get(0))
            .unwrap()
            .map(Result::unwrap)
            .collect()
    }

    fn relation_complete_marker(store: &SqliteStore, source_path: &str) -> bool {
        store
            .conn
            .borrow()
            .query_row(
                "SELECT EXISTS(
                     SELECT 1 FROM source_relation_scans WHERE source_path = ?1
                 )",
                [source_path],
                |row| row.get(0),
            )
            .unwrap()
    }

    thread_local! {
        static TRACED_STATEMENTS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    }

    /// 在该 store 的连接上挂 `SQLITE_TRACE_STMT` 钩子执行 `run`,返回期间执行的
    /// SQL 语句总数(prepare 不计;同一 prepared statement 每次执行都计一条)。
    /// 钩子是每连接独立的,测试各跑各的线程,互不干扰。
    pub(crate) fn counted_statements<R>(store: &SqliteStore, run: impl FnOnce() -> R) -> usize {
        TRACED_STATEMENTS.with(|cell| cell.set(0));
        {
            let conn = store.conn.borrow();
            conn.trace_v2(
                rusqlite::trace::TraceEventCodes::SQLITE_TRACE_STMT,
                Some(count_user_statement),
            );
        }
        let result = run();
        {
            let conn = store.conn.borrow();
            conn.trace_v2(rusqlite::trace::TraceEventCodes::empty(), None);
        }
        let _ = result;
        TRACED_STATEMENTS.with(|cell| cell.get())
    }

    /// `counted_statements` 的 trace 回调：只计用户层语句。SQLite 内部语句
    /// （FTS5 影子表查询、`PRAGMA data_version` 等）以 `--` 开头，不计入，
    /// 否则"pushdown 保持单语句"这类断言会被虚拟表内部执行数污染。
    fn count_user_statement(event: rusqlite::trace::TraceEvent<'_>) {
        match event {
            rusqlite::trace::TraceEvent::Stmt(_stmt, sql) if !sql.starts_with("--") => {
                TRACED_STATEMENTS.with(|cell| cell.set(cell.get() + 1));
            }
            _ => {}
        }
    }

    /// 大会话源批次:chain_len 条链式消息(除首条外每条带边指向前一条)+
    /// orphan_count 条孤儿父消息(Native 身份,入库但无出现,由带出现的子消息
    /// 指向),外加会话与文档条目。返回批次与孤儿父消息 id(供等级断言)。
    fn chain_source_batch(
        source_path: &str,
        session: &StableId,
        document: &StableId,
        chain_len: usize,
        orphan_count: usize,
    ) -> (SourceBatch, Vec<StableId>) {
        let mut entries = Vec::new();
        let mut placements = Vec::new();
        let mut edges = Vec::new();
        let chain_messages: Vec<StableId> = (0..chain_len)
            .map(|index| {
                sid(
                    IdKind::Message,
                    format!("{source_path}-chain-{index}").as_bytes(),
                )
            })
            .collect();
        for (index, message) in chain_messages.iter().enumerate() {
            entries.push(typed_message_entry(message, &format!("chain body {index}")));
            let placement = placement(
                session,
                document,
                message,
                index as u32,
                false,
                Some((0, 4)),
            );
            if index > 0 {
                edges.push(reply_edge(&placement, &chain_messages[index - 1]));
            }
            placements.push(placement);
        }
        let orphans: Vec<StableId> = (0..orphan_count)
            .map(|index| {
                StableId::native(IdKind::Message, &format!("{source_path}-orphan-{index}"))
            })
            .collect();
        for (index, orphan) in orphans.iter().enumerate() {
            entries.push(typed_message_entry(orphan, &format!("orphan body {index}")));
            let child = sid(
                IdKind::Message,
                format!("{source_path}-orphan-child-{index}").as_bytes(),
            );
            entries.push(typed_message_entry(
                &child,
                &format!("orphan child body {index}"),
            ));
            let child_placement = placement(
                session,
                document,
                &child,
                (chain_len + index) as u32,
                false,
                Some((0, 4)),
            );
            edges.push(reply_edge(&child_placement, orphan));
            placements.push(child_placement);
        }
        let placed_ids: Vec<&str> = placements
            .iter()
            .map(|placement| placement.message_id.as_str())
            .collect();
        entries.push((
            session.clone(),
            session_payload(document.as_str(), &placed_ids),
            String::new(),
        ));
        entries.push(typed_document_entry(document));
        (
            source_batch(source_path, entries, placements, edges, true),
            orphans,
        )
    }

    fn latest_index_batch(store: &SqliteStore) -> IndexBatch {
        let operation_id: String = store
            .conn
            .borrow()
            .query_row(
                "SELECT operation_id FROM index_batches
                 ORDER BY target_generation DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        store.index_batch(&operation_id).unwrap().unwrap()
    }

    #[test]
    fn catalog_put_get_roundtrip() {
        let store = SqliteStore::open_in_memory().unwrap();
        let id = sid(IdKind::Session, b"s1");
        assert!(store.get(&id).unwrap().is_none());
        store.put(&id, b"hello payload").unwrap();
        assert_eq!(store.get(&id).unwrap().unwrap(), b"hello payload");
    }

    #[test]
    fn catalog_put_overwrites() {
        let store = SqliteStore::open_in_memory().unwrap();
        let id = sid(IdKind::Session, b"s1");
        store.put(&id, b"first").unwrap();
        store.put(&id, b"second").unwrap();
        assert_eq!(store.get(&id).unwrap().unwrap(), b"second");
    }

    #[test]
    fn catalog_put_advances_generation() {
        // put 是内容变更：推进 generation，使此前签发的 search/list 游标在此变更
        // 后失效（游标绑定 generation 的 CAS 契约，与批量提交一致）。
        let store = SqliteStore::open_in_memory().unwrap();
        assert_eq!(store.active_generation().unwrap(), 0);
        let id = sid(IdKind::Session, b"s1");
        store.put(&id, b"payload").unwrap();
        assert_eq!(store.active_generation().unwrap(), 1);
        store.put(&id, b"updated").unwrap();
        assert_eq!(store.active_generation().unwrap(), 2);
        // SearchIndex::index 同样是索引写入，推进 generation。
        let message = sid(IdKind::Message, b"m1");
        store.index(&message, "needle").unwrap();
        assert_eq!(store.active_generation().unwrap(), 3);
    }

    #[test]
    fn catalog_get_many_preserves_order_and_misses() {
        let store = SqliteStore::open_in_memory().unwrap();
        let a = sid(IdKind::Message, b"gma");
        let b = sid(IdKind::Message, b"gmb");
        let missing = sid(IdKind::Message, b"missing");
        store.put(&a, b"payload-a").unwrap();
        store.put(&b, b"payload-b").unwrap();
        // 乱序请求：结果必须与请求同序（保序契约），目录中不存在的 id → None。
        let got = store
            .get_many(&[b.clone(), missing.clone(), a.clone()])
            .unwrap();
        assert_eq!(got.len(), 3);
        assert_eq!(got[0], (b, Some(b"payload-b".to_vec())));
        assert_eq!(got[1], (missing, None));
        assert_eq!(got[2], (a, Some(b"payload-a".to_vec())));
        // 空请求 → 空结果。
        assert!(store.get_many(&[]).unwrap().is_empty());
    }

    #[test]
    fn catalog_get_many_chunks_over_variable_limit() {
        let store = SqliteStore::open_in_memory().unwrap();
        // 501 个 id 跨过 BATCH_IN_CHUNK(500) 分块边界：两块 IN 都能正确取回。
        let mut ids: Vec<StableId> = Vec::new();
        for i in 0..501u32 {
            let id = sid(IdKind::Message, &i.to_le_bytes());
            store
                .put(&id, &format!("payload-{i}").into_bytes())
                .unwrap();
            ids.push(id);
        }
        let got = store.get_many(&ids).unwrap();
        assert_eq!(got.len(), 501);
        for (i, (id, payload)) in got.iter().enumerate() {
            assert_eq!(id, &ids[i]);
            assert_eq!(payload.as_deref(), Some(format!("payload-{i}").as_bytes()));
        }
    }

    /// 向 message_placements 直接插入一行（session_of 只读该表，无需 catalog/提交机制）。
    fn insert_placement(
        store: &SqliteStore,
        placement_id: &str,
        session: &StableId,
        document: &StableId,
        message: &StableId,
        source_ordinal: i64,
    ) {
        let conn = store.conn.borrow();
        conn.execute(
            "INSERT INTO message_placements(
                 placement_id, session_id, document_id, message_id,
                 source_ordinal, is_sidechain, byte_start, byte_end)
             VALUES (?1, ?2, ?3, ?4, ?5, 0, NULL, NULL)",
            rusqlite::params![
                placement_id,
                session.as_str(),
                document.as_str(),
                message.as_str(),
                source_ordinal,
            ],
        )
        .unwrap();
    }

    #[test]
    fn session_of_resolves_owning_session_batched_and_order_preserving() {
        let store = SqliteStore::open_in_memory().unwrap();
        let session_a = sid(IdKind::Session, b"owner-session-a");
        let session_b = sid(IdKind::Session, b"owner-session-b");
        let document = sid(IdKind::Document, b"owner-document");
        let msg_only_a = sid(IdKind::Message, b"owner-msg-only-a");
        let msg_both = sid(IdKind::Message, b"owner-msg-both");
        let msg_none = sid(IdKind::Message, b"owner-msg-none");
        insert_placement(
            &store,
            "plc_v1_owner_0",
            &session_a,
            &document,
            &msg_only_a,
            0,
        );
        insert_placement(
            &store,
            "plc_v1_owner_1",
            &session_a,
            &document,
            &msg_both,
            1,
        );
        insert_placement(
            &store,
            "plc_v1_owner_2",
            &session_b,
            &document,
            &msg_both,
            0,
        );

        // 乱序请求：结果与请求同序；msg_both 在两个会话都有 placement →
        // 确定性取 wire id 字典序最小的会话（跨页稳定）；msg_none 无 placement → None。
        let got = store
            .session_of(&[msg_both.clone(), msg_none.clone(), msg_only_a.clone()])
            .unwrap();
        let expected_both = [session_a.as_str(), session_b.as_str()]
            .iter()
            .min()
            .unwrap()
            .to_string();
        assert_eq!(got.len(), 3);
        assert_eq!(got[0].0, msg_both);
        assert_eq!(
            got[0].1.as_ref().map(StableId::as_str),
            Some(expected_both.as_str())
        );
        assert_eq!(got[1].0, msg_none);
        assert_eq!(got[1].1, None);
        assert_eq!(got[2].0, msg_only_a);
        // 会话经 wire 往返重建（from_wire → Unstable tier），按 wire 串比较。
        assert_eq!(
            got[2].1.as_ref().map(StableId::as_str),
            Some(session_a.as_str())
        );
        // 空请求 → 空结果。
        assert!(store.session_of(&[]).unwrap().is_empty());
    }

    #[test]
    fn session_of_chunks_over_variable_limit() {
        let store = SqliteStore::open_in_memory().unwrap();
        let session = sid(IdKind::Session, b"chunk-session");
        let document = sid(IdKind::Document, b"chunk-document");
        // 501 个消息跨过 BATCH_IN_CHUNK(500) 分块边界：两块 GROUP BY 查询都取回。
        let mut ids: Vec<StableId> = Vec::new();
        for i in 0..501u32 {
            let id = sid(IdKind::Message, &i.to_le_bytes());
            insert_placement(
                &store,
                &format!("plc_v1_chunk_{i}"),
                &session,
                &document,
                &id,
                i as i64,
            );
            ids.push(id);
        }
        let got = store.session_of(&ids).unwrap();
        assert_eq!(got.len(), 501);
        for (i, (id, owner)) in got.iter().enumerate() {
            assert_eq!(id, &ids[i]);
            assert_eq!(owner.as_ref().map(StableId::as_str), Some(session.as_str()));
        }
    }

    #[test]
    fn search_finds_indexed_and_rebuilds_id() {
        let store = SqliteStore::open_in_memory().unwrap();
        let id = sid(IdKind::Message, b"m1");
        store.index(&id, "the quick brown fox").unwrap();
        let hits = store.query("brown", 10).unwrap();
        assert_eq!(hits.len(), 1);
        // 关键：从 FTS 取回的 id 与原 id 完全相等（含 kind/stability），
        // 证明 serde JSON 往返无损。
        assert_eq!(hits[0].id, id);
        assert_eq!(hits[0].id.kind(), IdKind::Message);
        assert_eq!(hits[0].id.stability(), Stability::Reconstructed);
    }

    #[test]
    fn reindex_is_idempotent() {
        let store = SqliteStore::open_in_memory().unwrap();
        let id = sid(IdKind::Message, b"m1");
        store.index(&id, "alpha beta").unwrap();
        store.index(&id, "alpha gamma").unwrap();
        // 重索引后旧文本不再命中，新文本命中，且不产生重复行。
        assert!(store.query("beta", 10).unwrap().is_empty());
        assert_eq!(store.query("gamma", 10).unwrap().len(), 1);
        assert_eq!(store.query("alpha", 10).unwrap().len(), 1);
    }

    // ─── CJK bigram（ADR-0007）───

    #[test]
    fn cjk_bigram_recall_hits_two_char_queries_in_longer_sentences() {
        // R1.4：双字查询"配置"/"数据库"命中包含它们的长句。索引侧与查询侧
        // 同一 bigram transform：整段汉字从 1 个 FTS 词元变成相邻两字 bigram
        // 词元（"配置数据库迁移" → "配置 置数 数据 据库 库迁 迁移"）。
        let store = SqliteStore::open_in_memory().unwrap();
        let id = sid(IdKind::Message, b"cjk-m1");
        store
            .index(&id, "我们已经在生产环境配置了数据库迁移，备份策略也更新了")
            .unwrap();
        for query in ["配置", "数据库", "备份", "迁移", "策略"] {
            let hits = store.query(query, 10).unwrap();
            assert_eq!(hits.len(), 1, "query {query:?} must recall the message");
            assert_eq!(hits[0].id, id);
        }
        // 多字查询按 bigram 并集 AND 匹配。
        assert_eq!(store.query("数据库迁移", 10).unwrap().len(), 1);
        // 不存在的双字组合不命中。
        assert!(store.query("翻墙", 10).unwrap().is_empty());
        // 单字 CJK 查询仍弱（已知边界，ADR-0007 §后果）：transform 后为空串，
        // 无结果且不触发 FTS 语法错误。
        assert!(store.query("了", 10).unwrap().is_empty());
    }

    #[test]
    fn cjk_bigram_applies_on_source_batch_sync_path() {
        // 真实 ingest 路径（SourceBatch → commit_source_batches_if_changed）
        // 的 fts 写入与单条 SearchIndex::index 共用同一索引侧 transform。
        let store = SqliteStore::open_in_memory().unwrap();
        let session = sid(IdKind::Session, b"cjk-ses");
        let document = sid(IdKind::Document, b"cjk-doc");
        let message = sid(IdKind::Message, b"cjk-msg");
        let source = source_batch(
            "cjk-sync.jsonl",
            vec![
                entity_entry(&session),
                entity_entry(&document),
                typed_message_entry(&message, "启动服务时记得检查配置文件的路径"),
            ],
            vec![placement(
                &session,
                &document,
                &message,
                0,
                false,
                Some((0, 4)),
            )],
            Vec::new(),
            true,
        );
        let changed = store
            .commit_source_batches_if_changed(std::slice::from_ref(&source))
            .unwrap();
        assert!(changed);
        assert_eq!(store.query("配置", 10).unwrap().len(), 1);
        assert_eq!(store.query("路径", 10).unwrap().len(), 1);
        assert_eq!(store.query("配置文件", 10).unwrap().len(), 1);

        // 内容级 no-op：再次同步同一源不推进 generation——current 判定对 fts
        // 存储的 bigram 正文与同一 transform 后的 batch text 比较（若只比原文，
        // 已同步的源每次重同步都会被误判为 not-current 而反复推进 generation）。
        let generation = store.active_generation().unwrap();
        let again = store
            .commit_source_batches_if_changed(std::slice::from_ref(&source))
            .unwrap();
        assert!(!again, "unchanged re-sync must be a no-op");
        assert_eq!(store.active_generation().unwrap(), generation);
    }

    #[test]
    fn cjk_bigram_rebuild_reprojects_from_catalog_and_bumps_generation() {
        // R1.2：rebuild 从权威 catalog 重投影 FTS（searchable_text + 同一索引侧
        // transform），无 schema 变更、无 catalog 迁移；重建推进 generation
        // （旧 cursor 因此失效——正常契约行为）。
        // 词元增长：消息正文"今天把数据库备份到了新目录"（11 字）从 1 个整段
        // 词元变为 10 个 bigram 词元——纯 CJK 文本约 2x 最坏增长（ADR-0007 §后果）。
        let store = SqliteStore::open_in_memory().unwrap();
        let session = sid(IdKind::Session, b"rebuild-ses");
        let document = sid(IdKind::Document, b"rebuild-doc");
        let message = sid(IdKind::Message, b"rebuild-msg");
        let source = source_batch(
            "rebuild-cjk.jsonl",
            vec![
                entity_entry(&session),
                entity_entry(&document),
                typed_message_entry(&message, "今天把数据库备份到了新目录"),
            ],
            vec![placement(
                &session,
                &document,
                &message,
                0,
                false,
                Some((0, 4)),
            )],
            Vec::new(),
            true,
        );
        store
            .commit_source_batches_if_changed(std::slice::from_ref(&source))
            .unwrap();
        assert_eq!(store.query("数据库", 10).unwrap().len(), 1);

        let generation_before = store.active_generation().unwrap();
        let n = store.rebuild_index().unwrap();
        assert_eq!(n, 3, "rebuild 应从 catalog 重投影全部 3 个实体");
        assert_eq!(
            store.active_generation().unwrap(),
            generation_before + 1,
            "rebuild 必须推进 generation"
        );
        // rebuild 后 CJK 依旧可搜（同一 searchable_text 投影 + 同一 transform）。
        assert_eq!(store.query("数据库", 10).unwrap().len(), 1);
        assert_eq!(store.query("备份", 10).unwrap().len(), 1);
        assert_eq!(store.query("新目录", 10).unwrap().len(), 1);
    }

    #[test]
    fn cjk_bigram_keeps_ascii_path_and_punctuation_literals_unchanged() {
        // R1.3（ADR-0003）：纯 ASCII/路径/标点输入不含汉字，bigram_cjk 原样
        // 返回——字面量化语义与之前逐字节一致，FTS 词元不变。
        let store = SqliteStore::open_in_memory().unwrap();
        let id = sid(IdKind::Message, b"literal");
        store
            .index(&id, "check C:\\Users\\dev\\mcp.json config:backup")
            .unwrap();
        for query in ["mcp.json", "config:backup", "Users", "backup", "check"] {
            let hits = store.query(query, 10).unwrap();
            assert_eq!(hits.len(), 1, "query {query:?} must recall");
            assert_eq!(hits[0].id, id);
        }
        // 标点/操作符仍按字面量处理，不泄漏 FTS 语法错误。
        for query in ["a:b", "x-y", "prefix*", "AND OR NOT", "* - :"] {
            assert!(store.query(query, 10).unwrap().is_empty(), "{query:?}");
        }
        // 汉字与 ASCII 混合的内容两侧变换一致："配置v2.0" → "配置 v2.0" AND 匹配。
        let mixed = sid(IdKind::Message, b"cjk-mixed");
        store.index(&mixed, "使用配置v2.0备份").unwrap();
        assert_eq!(store.query("配置v2.0", 10).unwrap().len(), 1);
        assert_eq!(store.query("v2.0", 10).unwrap().len(), 1);
    }

    #[test]
    fn raw_han_sentence_is_one_token_without_bigram_transform() {
        // 对照基线（bigram 落地前的旧行为）：未经 transform 的原始正文经
        // unicode61 把整段汉字当一个词元，"配置"/"数据库"这类双字查询无法
        // 命中（ADR-0007 实证：中文召回 8-33%）。此 fixture 证明 recall 提升
        // 来自索引侧 transform 本身，而不是查询侧的特判；同时防止将来有人
        // 只回退写入侧、留下查询侧变换造成两侧错配。
        let store = SqliteStore::open_in_memory().unwrap();
        let id = sid(IdKind::Message, b"raw-han");
        let id_json = serde_json::to_string(&id).unwrap();
        {
            let conn = store.conn.borrow();
            conn.execute(
                "INSERT INTO fts(id, text) VALUES(?1, ?2)",
                rusqlite::params![
                    id_json,
                    "我们已经在生产环境配置了数据库迁移，备份策略也更新了"
                ],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO fts_ids(wire_id, id_json, fts_rowid) VALUES(?1, ?2, NULL)",
                rusqlite::params![id.as_str(), serde_json::to_string(&id).unwrap()],
            )
            .unwrap();
        }
        assert!(store.query("配置", 10).unwrap().is_empty());
        assert!(store.query("数据库", 10).unwrap().is_empty());
        assert!(store.query("迁移", 10).unwrap().is_empty());
    }

    #[test]
    fn query_respects_limit() {
        let store = SqliteStore::open_in_memory().unwrap();
        for i in 0..5u32 {
            let id = sid(IdKind::Message, &i.to_le_bytes());
            store.index(&id, "shared term").unwrap();
        }
        assert_eq!(store.query("shared", 3).unwrap().len(), 3);
    }

    #[test]
    fn fresh_db_reports_current_schema_version() {
        let store = SqliteStore::open_in_memory().unwrap();
        assert_eq!(store.schema_version().unwrap(), SCHEMA_VERSION);
    }

    #[test]
    fn reopen_preserves_data_and_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("catalog.db");
        let p = path.to_string_lossy().into_owned();
        // 用 Message id：非 Message 实体不进 fts 全文表（kind 门，见 index/put）。
        let id = sid(IdKind::Message, b"s1");
        {
            let store = SqliteStore::open(&p).unwrap();
            store.put(&id, b"persisted").unwrap();
            store.index(&id, "persisted body").unwrap();
        }
        // 重开：migration 幂等（IF NOT EXISTS 已换成版本门控），数据与版本不变。
        let store = SqliteStore::open(&p).unwrap();
        assert_eq!(store.schema_version().unwrap(), SCHEMA_VERSION);
        assert_eq!(store.get(&id).unwrap().unwrap(), b"persisted");
        assert_eq!(store.query("persisted", 10).unwrap().len(), 1);
    }

    #[test]
    fn newer_schema_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("future.db");
        let p = path.to_string_lossy().into_owned();
        // 先正常建库，再把 user_version 拨到未来版本，模拟更新的二进制写过的库。
        SqliteStore::open(&p).unwrap();
        {
            let conn = rusqlite::Connection::open(&p).unwrap();
            conn.execute_batch(&format!("PRAGMA user_version = {};", SCHEMA_VERSION + 1))
                .unwrap();
        }
        // 旧二进制拒绝打开更新版本的库，而非按旧 schema 误读。
        // 用 match 而非 unwrap_err()——SqliteStore 内含 Connection，不实现 Debug。
        let err = match SqliteStore::open(&p) {
            Err(e) => e,
            Ok(_) => panic!("expected newer schema to be rejected"),
        };
        assert!(
            matches!(err, PortError::SchemaIncompatible(m) if m.contains("newer than supported"))
        );
    }

    #[test]
    fn v6_db_migrates_to_v7_without_fabricating_relations() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v6.db");
        let p = path.to_string_lossy().into_owned();
        let payload = vec![0x00, 0xff, 0x7f, 0x01, 0x80];
        {
            let conn = rusqlite::Connection::open(&p).unwrap();
            create_v6_schema(&conn);
            conn.execute(
                "INSERT INTO catalog(id, payload) VALUES('msg_v1_legacy', ?1)",
                [&payload],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO source_membership(source_path, message_id, document_id)
                 VALUES('legacy.jsonl', 'msg_v1_legacy', NULL)",
                [],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO source_scans(source_path, scanned_at_ms)
                 VALUES('legacy.jsonl', 1)",
                [],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO index_batches(
                     operation_id, base_generation, target_generation, state,
                     operation_digest, upsert_ids_json, delete_ids_json,
                     durable_point, created_at_ms, committed_at_ms
                 ) VALUES(
                     'legacy-op', 0, 1, 'activated', 'legacy-digest', '[]', '[]',
                     'activated', 1, 2
                 )",
                [],
            )
            .unwrap();
        }

        let store = SqliteStore::open(&p).unwrap();
        assert_eq!(store.schema_version().unwrap(), SCHEMA_VERSION);
        let id = StableId::from_wire("msg_v1_legacy").unwrap();
        assert_eq!(store.get(&id).unwrap().unwrap(), payload);
        let batch = store.index_batch("legacy-op").unwrap().unwrap();
        assert!(batch.relation_upserts.is_empty());
        assert!(batch.relation_deletes.is_empty());
        assert!(batch.source_replacements.is_empty());
        drop(store);

        let conn = rusqlite::Connection::open(&p).unwrap();
        let document_id: Option<String> = conn
            .query_row(
                "SELECT document_id FROM source_membership
                 WHERE source_path = 'legacy.jsonl' AND message_id = 'msg_v1_legacy'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(document_id, None);

        for table in [
            "message_placements",
            "message_edges",
            "source_placement_membership",
            "source_relation_scans",
        ] {
            let count: i64 = conn
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                    row.get(0)
                })
                .unwrap();
            assert_eq!(count, 0, "{table} must start empty");
        }
        let relation_scan_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM source_relation_scans", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(relation_scan_count, 0);

        let manifests: (String, String, String) = conn
            .query_row(
                "SELECT relation_upserts_json, relation_deletes_json,
                        source_replacements_json
                 FROM index_batches WHERE operation_id = 'legacy-op'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(
            manifests,
            ("[]".to_string(), "[]".to_string(), "[]".to_string())
        );

        let mut stmt = conn
            .prepare(
                "SELECT name FROM sqlite_master
                 WHERE type = 'index' AND name IN (
                     'message_placements_session_order',
                     'message_placements_message',
                     'message_placements_document',
                     'source_placement_membership_placement'
                 )
                 ORDER BY name",
            )
            .unwrap();
        let indexes: Vec<String> = stmt
            .query_map([], |row| row.get(0))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        assert_eq!(
            indexes,
            vec![
                "message_placements_document",
                "message_placements_message",
                "message_placements_session_order",
                "source_placement_membership_placement",
            ]
        );
    }

    #[test]
    fn injected_v6_to_v7_failure_rolls_back_schema_and_version() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        create_v6_schema(&conn);

        let err = SqliteStore::migrate_v6_to_v7_inner(&conn, true).unwrap_err();
        assert!(
            matches!(err, PortError::Backend(message) if message.contains("injected v6-to-v7"))
        );
        assert!(conn.is_autocommit());
        let version: i64 = conn
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(version, 6);

        for table in [
            "message_placements",
            "message_edges",
            "source_placement_membership",
            "source_relation_scans",
        ] {
            let exists: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_master
                     WHERE type = 'table' AND name = ?1",
                    [table],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(exists, 0, "{table} must roll back");
        }
        let mut stmt = conn.prepare("PRAGMA table_info(index_batches)").unwrap();
        let columns: Vec<String> = stmt
            .query_map([], |row| row.get(1))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        assert!(!columns.iter().any(|name| {
            matches!(
                name.as_str(),
                "relation_upserts_json" | "relation_deletes_json" | "source_replacements_json"
            )
        }));
    }

    #[test]
    fn commit_batch_writes_all_entries() {
        let store = SqliteStore::open_in_memory().unwrap();
        let a = sid(IdKind::Message, b"a");
        let b = sid(IdKind::Message, b"b");
        store
            .commit_batch(&[
                (a.clone(), b"role\talpha".to_vec(), "alpha text".into()),
                (b.clone(), b"role\tbeta".to_vec(), "beta text".into()),
            ])
            .unwrap();
        assert_eq!(store.get(&a).unwrap().unwrap(), b"role\talpha");
        assert_eq!(store.get(&b).unwrap().unwrap(), b"role\tbeta");
        assert_eq!(store.query("alpha", 10).unwrap().len(), 1);
        assert_eq!(store.query("beta", 10).unwrap().len(), 1);
    }

    #[test]
    fn commit_batch_is_idempotent() {
        let store = SqliteStore::open_in_memory().unwrap();
        let id = sid(IdKind::Message, b"m");
        let entry = [(id.clone(), b"role\tv1".to_vec(), "version one".into())];
        store.commit_batch(&entry).unwrap();
        let entry2 = [(id.clone(), b"role\tv2".to_vec(), "version two".into())];
        store.commit_batch(&entry2).unwrap();
        assert_eq!(store.get(&id).unwrap().unwrap(), b"role\tv2");
        assert!(store.query("one", 10).unwrap().is_empty());
        assert_eq!(store.query("two", 10).unwrap().len(), 1);
    }

    #[test]
    fn batched_commit_rows_match_sequential_commit_rows() {
        // 批量 INSERT（多行 VALUES，100 行/块，见 BULK_INSERT_ROWS_PER_CHUNK）
        // 与逐行 INSERT 必须落出相同的 catalog/fts/fts_ids/placement/edge 行。
        // Store A 把整个 fixture 一次提交（256 实体 → 3 个 100 行块，走多行
        // 批量语句）；Store B 逐实体提交（每批 1 条 entry/placement/edge →
        // 逐行语句形状）。源级表（source_scans/source_membership 等）因源路径
        // 分布按设计不同而不比较；会话/文档容器 payload 的兼容别名按源拓扑
        // 重投影（document_id 归属不同），也不比较——消息 payload 必须逐字节相同。
        let session = sid(IdKind::Session, b"batch-equiv-session");
        let document = sid(IdKind::Document, b"batch-equiv-document");
        let (source, _) = chain_source_batch("batched.jsonl", &session, &document, 250, 2);
        assert!(
            source.entries.len() > 200 && source.placements.len() > 200,
            "fixture must span multiple 100-row chunks, got {} entries / {} placements",
            source.entries.len(),
            source.placements.len()
        );

        // Store A：单次大批次提交（多行批量路径）。
        let store_a = SqliteStore::open_in_memory().unwrap();
        store_a
            .commit_source_batches_if_changed(std::slice::from_ref(&source))
            .unwrap();

        // Store B：逐实体提交（每批 1 条 entry → 逐行语句形状）。
        let store_b = SqliteStore::open_in_memory().unwrap();
        let mut container_entries: Vec<(StableId, Vec<u8>, String)> = source
            .entries
            .iter()
            .filter(|(id, _, _)| id.kind() != IdKind::Message)
            .cloned()
            .collect();
        container_entries.sort_by(|left, right| left.0.as_str().cmp(right.0.as_str()));
        // 会话与文档实体必须先提交：placement 完整性校验要求被引用的
        // session/document/message 实体已存在于 catalog。
        for (index, entry) in container_entries.iter().enumerate() {
            let batch = source_batch(
                &format!("seq-container-{index}.jsonl"),
                vec![entry.clone()],
                vec![],
                vec![],
                true,
            );
            store_b
                .commit_source_batches_if_changed(std::slice::from_ref(&batch))
                .unwrap();
        }
        let message_entries: Vec<(StableId, Vec<u8>, String)> = source
            .entries
            .iter()
            .filter(|(id, _, _)| id.kind() == IdKind::Message)
            .cloned()
            .collect();
        for (index, entry) in message_entries.iter().enumerate() {
            let placements: Vec<MessagePlacement> = source
                .placements
                .iter()
                .filter(|placement| placement.message_id == entry.0)
                .cloned()
                .collect();
            let edges: Vec<MessageEdge> = source
                .edges
                .iter()
                .filter(|edge| {
                    placements
                        .iter()
                        .any(|placement| placement.id == edge.child_placement_id)
                })
                .cloned()
                .collect();
            let batch = source_batch(
                &format!("seq-msg-{index:04}.jsonl"),
                vec![entry.clone()],
                placements,
                edges,
                true,
            );
            store_b
                .commit_source_batches_if_changed(std::slice::from_ref(&batch))
                .unwrap();
        }

        // 实体级表行数相等。
        for table in [
            "catalog",
            "fts",
            "fts_ids",
            "message_placements",
            "message_edges",
        ] {
            assert_eq!(
                table_count(&store_a, table),
                table_count(&store_b, table),
                "{table} row count must match between batched and sequential commits"
            );
        }
        // 源级表按设计不同：Store A 1 个源，Store B 逐实体一源。
        assert_eq!(table_count(&store_a, "source_scans"), 1);
        assert_eq!(
            table_count(&store_b, "source_scans"),
            (message_entries.len() + container_entries.len()) as i64
        );

        // 消息 payload 逐实体相等（容器实体的兼容别名按源拓扑重投影，跳过）。
        let catalog_payloads = |store: &SqliteStore| -> BTreeMap<String, Vec<u8>> {
            let conn = store.conn.borrow();
            let mut stmt = conn
                .prepare("SELECT id, payload FROM catalog ORDER BY id")
                .unwrap();
            stmt.query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?))
            })
            .unwrap()
            .map(Result::unwrap)
            .filter(|(wire, _)| !wire.starts_with("ses_v1_") && !wire.starts_with("doc_v1_"))
            .collect()
        };
        assert_eq!(catalog_payloads(&store_a), catalog_payloads(&store_b));

        // fts 正文逐实体相等（fts 存 id_json + bigram 正文）。
        let fts_rows = |store: &SqliteStore| -> BTreeMap<String, String> {
            let conn = store.conn.borrow();
            let mut stmt = conn
                .prepare("SELECT id, text FROM fts ORDER BY id")
                .unwrap();
            stmt.query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .unwrap()
            .map(Result::unwrap)
            .collect()
        };
        assert_eq!(fts_rows(&store_a), fts_rows(&store_b));

        // fts_ids 边车逐实体相等（wire_id → id_json）。fts_rowid 是 FTS 内部
        // 物理 rowid，批量和顺序插入的分配顺序可以不同，不属于目录语义；下方
        // 另行断言每个 store 内部的 rowid 指向关系完整。
        let fts_ids_rows = |store: &SqliteStore| -> BTreeMap<String, String> {
            let conn = store.conn.borrow();
            let mut stmt = conn
                .prepare("SELECT wire_id, id_json FROM fts_ids ORDER BY wire_id")
                .unwrap();
            stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
                .unwrap()
                .map(Result::unwrap)
                .collect()
        };
        assert_eq!(fts_ids_rows(&store_a), fts_ids_rows(&store_b));
        for store in [&store_a, &store_b] {
            let mismatched: i64 = store
                .conn
                .borrow()
                .query_row(
                    "SELECT COUNT(*) FROM fts f
                     JOIN fts_ids fi ON fi.id_json = f.id
                     WHERE fi.fts_rowid IS NULL OR fi.fts_rowid != f.rowid",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(
                mismatched, 0,
                "fts_ids.fts_rowid must match the fts row's actual rowid"
            );
        }

        // placements 全列相等。
        let placement_rows = |store: &SqliteStore| -> Vec<PlacementSnapshotRow> {
            let conn = store.conn.borrow();
            let mut stmt = conn
                .prepare(
                    "SELECT placement_id, session_id, document_id, message_id,
                                source_ordinal, is_sidechain, byte_start, byte_end
                         FROM message_placements ORDER BY placement_id",
                )
                .unwrap();
            stmt.query_map([], |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                ))
            })
            .unwrap()
            .map(Result::unwrap)
            .collect()
        };
        assert_eq!(placement_rows(&store_a), placement_rows(&store_b));

        // edges 全列相等。
        let edge_rows = |store: &SqliteStore| -> Vec<(String, String, Option<String>, String)> {
            let conn = store.conn.borrow();
            let mut stmt = conn
                .prepare(
                    "SELECT child_placement_id, parent_message_id, parent_native_id, relation
                         FROM message_edges ORDER BY child_placement_id",
                )
                .unwrap();
            stmt.query_map([], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
            })
            .unwrap()
            .map(Result::unwrap)
            .collect()
        };
        assert_eq!(edge_rows(&store_a), edge_rows(&store_b));
    }

    #[test]
    fn relation_and_marker_only_changes_advance_once_then_noop() {
        let store = SqliteStore::open_in_memory().unwrap();
        let session = sid(IdKind::Session, b"relation-generation-session");
        let document = sid(IdKind::Document, b"relation-generation-document");
        let parent = sid(IdKind::Message, b"relation-generation-parent");
        let child = sid(IdKind::Message, b"relation-generation-child");
        let child_placement = placement(&session, &document, &child, 1, false, Some((10, 20)));
        let entries = || {
            [&session, &document, &parent, &child]
                .into_iter()
                .map(entity_entry)
                .collect()
        };

        let initial = source_batch(
            "relation-generation.jsonl",
            entries(),
            vec![child_placement.clone()],
            Vec::new(),
            true,
        );
        assert!(
            store
                .commit_source_batches_if_changed(std::slice::from_ref(&initial))
                .unwrap()
        );
        assert_eq!(store.active_generation().unwrap(), 1);

        let edge = reply_edge(&child_placement, &parent);
        let relation_only = source_batch(
            "relation-generation.jsonl",
            entries(),
            vec![child_placement.clone()],
            vec![edge.clone()],
            true,
        );
        assert!(
            store
                .commit_source_batches_if_changed(std::slice::from_ref(&relation_only))
                .unwrap()
        );
        assert_eq!(store.active_generation().unwrap(), 2);
        let relation_batch = latest_index_batch(&store);
        assert_eq!(relation_batch.relation_upserts.len(), 2);
        assert!(relation_batch.relation_deletes.is_empty());
        assert_eq!(relation_batch.source_replacements.len(), 1);

        assert!(
            !store
                .commit_source_batches_if_changed(std::slice::from_ref(&relation_only))
                .unwrap()
        );
        assert_eq!(store.active_generation().unwrap(), 2);

        let marker_only = source_batch(
            "relation-generation.jsonl",
            entries(),
            vec![child_placement.clone()],
            vec![edge.clone()],
            false,
        );
        assert!(
            store
                .commit_source_batches_if_changed(std::slice::from_ref(&marker_only))
                .unwrap()
        );
        assert_eq!(store.active_generation().unwrap(), 3);
        assert!(!relation_complete_marker(
            &store,
            "relation-generation.jsonl"
        ));
        assert_eq!(
            latest_index_batch(&store).source_replacements[0]["relation_complete"],
            serde_json::Value::Bool(false)
        );

        assert!(
            !store
                .commit_source_batches_if_changed(std::slice::from_ref(&marker_only))
                .unwrap()
        );
        assert_eq!(store.active_generation().unwrap(), 3);

        assert!(
            store
                .commit_source_batches_if_changed(std::slice::from_ref(&relation_only))
                .unwrap()
        );
        assert_eq!(store.active_generation().unwrap(), 4);
        assert!(relation_complete_marker(
            &store,
            "relation-generation.jsonl"
        ));
    }

    #[test]
    fn complete_relations_regenerate_divergent_context_aliases_without_stable_conflict() {
        let store = SqliteStore::open_in_memory().unwrap();
        let session_a = sid(IdKind::Session, b"compat-session-a");
        let session_b = sid(IdKind::Session, b"compat-session-b");
        let document_a = sid(IdKind::Document, b"compat-document-a");
        let document_b = sid(IdKind::Document, b"compat-document-b");
        let parent_a = sid(IdKind::Message, b"compat-parent-a");
        let parent_b = sid(IdKind::Message, b"compat-parent-b");
        let child = sid(IdKind::Message, b"compat-child");
        let placement_a = placement(&session_a, &document_a, &child, 1, false, Some((10, 20)));
        let placement_b = placement(&session_b, &document_b, &child, 2, true, Some((30, 40)));
        let edge_a = MessageEdge {
            child_placement_id: placement_a.id.clone(),
            parent_message_id: parent_a.clone(),
            parent_native_id: Some("native-parent-a".into()),
            relation: MessageRelation::Reply,
        };
        let edge_b = MessageEdge {
            child_placement_id: placement_b.id.clone(),
            parent_message_id: parent_b.clone(),
            parent_native_id: Some("native-parent-b".into()),
            relation: MessageRelation::Reply,
        };
        let sources = [
            source_batch(
                "compat-a.jsonl",
                vec![
                    (
                        child.clone(),
                        relational_message_payload(
                            &session_a,
                            &document_a,
                            &parent_a,
                            "native-parent-a",
                            false,
                            (10, 20),
                        ),
                        "shared stable body".into(),
                    ),
                    (
                        session_a.clone(),
                        session_payload(document_a.as_str(), &[child.as_str()]),
                        String::new(),
                    ),
                    entity_entry(&document_a),
                    entity_entry(&parent_a),
                ],
                vec![placement_a.clone()],
                vec![edge_a],
                true,
            ),
            source_batch(
                "compat-b.jsonl",
                vec![
                    (
                        child.clone(),
                        relational_message_payload(
                            &session_b,
                            &document_b,
                            &parent_b,
                            "native-parent-b",
                            true,
                            (30, 40),
                        ),
                        "shared stable body".into(),
                    ),
                    (
                        session_b.clone(),
                        session_payload(document_b.as_str(), &[child.as_str()]),
                        String::new(),
                    ),
                    entity_entry(&document_b),
                    entity_entry(&parent_b),
                ],
                vec![placement_b.clone()],
                vec![edge_b],
                true,
            ),
        ];
        assert!(store.commit_source_batches_if_changed(&sources).unwrap());

        let stored: serde_json::Value =
            serde_json::from_slice(&store.get(&child).unwrap().unwrap()).unwrap();
        assert_eq!(stored["parent"], serde_json::Value::Null);
        assert_eq!(stored["parent_native_id"], serde_json::Value::Null);
        assert_eq!(stored["is_sidechain"], serde_json::Value::Null);
        assert_eq!(stored["sessions"].as_array().unwrap().len(), 2);
        let spans = stored["spans"].as_array().unwrap();
        assert_eq!(spans.len(), 2);
        assert!(
            spans
                .iter()
                .any(|span| span["placement_id"] == placement_a.id.as_str())
        );
        assert!(
            spans
                .iter()
                .any(|span| span["placement_id"] == placement_b.id.as_str())
        );

        let generation = store.active_generation().unwrap();
        assert!(!store.commit_source_batches_if_changed(&sources).unwrap());
        assert_eq!(store.active_generation().unwrap(), generation);
    }

    #[test]
    fn alias_regeneration_is_scoped_to_batch_sources_and_skips_unchanged_rows() {
        // P0-1: regenerating aliases for the whole catalog per batch made
        // first ingest O(n²). Only entities whose claimers intersect the
        // batch's sources may be rewritten, and a rewrite whose bytes are
        // unchanged must not hit the UPDATE (WAL stays flat).
        let store = SqliteStore::open_in_memory().unwrap();
        let session_a = sid(IdKind::Session, b"scope-session-a");
        let document_a = sid(IdKind::Document, b"scope-document-a");
        let parent_a = sid(IdKind::Message, b"scope-parent-a");
        let child_a = sid(IdKind::Message, b"scope-child-a");
        let placement_a = placement(&session_a, &document_a, &child_a, 1, false, Some((10, 20)));
        let edge_a = MessageEdge {
            child_placement_id: placement_a.id.clone(),
            parent_message_id: parent_a.clone(),
            parent_native_id: Some("native-parent-a".into()),
            relation: MessageRelation::Reply,
        };
        let batch_a = source_batch(
            "scope-a.jsonl",
            vec![
                (
                    child_a.clone(),
                    relational_message_payload(
                        &session_a,
                        &document_a,
                        &parent_a,
                        "native-parent-a",
                        false,
                        (10, 20),
                    ),
                    // entry text 必须与 payload 内嵌 text 一致（生产 CLI 恒等）：
                    // 合并路径按 searchable_text(payload) 重投影 FTS，不一致的
                    // fixture 会把重同步误判为需要"修复"fts 文本而推进 generation。
                    "shared stable body".into(),
                ),
                (
                    session_a.clone(),
                    session_payload(document_a.as_str(), &[child_a.as_str()]),
                    String::new(),
                ),
                entity_entry(&document_a),
                entity_entry(&parent_a),
            ],
            vec![placement_a.clone()],
            vec![edge_a],
            true,
        );
        assert!(
            store
                .commit_source_batches_if_changed(std::slice::from_ref(&batch_a))
                .unwrap()
        );

        // Second batch touches only source B; entity A's stored payload must
        // remain byte-identical after commit B.
        let session_b = sid(IdKind::Session, b"scope-session-b");
        let document_b = sid(IdKind::Document, b"scope-document-b");
        let parent_b = sid(IdKind::Message, b"scope-parent-b");
        let child_b = sid(IdKind::Message, b"scope-child-b");
        let placement_b = placement(&session_b, &document_b, &child_b, 1, false, Some((30, 40)));
        let edge_b = MessageEdge {
            child_placement_id: placement_b.id.clone(),
            parent_message_id: parent_b.clone(),
            parent_native_id: Some("native-parent-b".into()),
            relation: MessageRelation::Reply,
        };
        let batch_b = source_batch(
            "scope-b.jsonl",
            vec![
                (
                    child_b.clone(),
                    relational_message_payload(
                        &session_b,
                        &document_b,
                        &parent_b,
                        "native-parent-b",
                        false,
                        (30, 40),
                    ),
                    "shared stable body".into(),
                ),
                (
                    session_b.clone(),
                    session_payload(document_b.as_str(), &[child_b.as_str()]),
                    String::new(),
                ),
                entity_entry(&document_b),
                entity_entry(&parent_b),
            ],
            vec![placement_b.clone()],
            vec![edge_b],
            true,
        );
        let stored_a_before = store.get(&child_a).unwrap().unwrap();
        assert!(store.commit_source_batches_if_changed(&[batch_b]).unwrap());
        let stored_a_after = store.get(&child_a).unwrap().unwrap();
        assert_eq!(
            stored_a_before, stored_a_after,
            "entity owned only by an untouched source must not be rewritten"
        );
        // And a full re-sync of A is a no-op that does not advance generation.
        let generation = store.active_generation().unwrap();
        assert!(!store.commit_source_batches_if_changed(&[batch_a]).unwrap());
        assert_eq!(store.active_generation().unwrap(), generation);
    }

    #[test]
    fn mixed_relation_completeness_preserves_alias_until_last_contributor_is_complete() {
        let store = SqliteStore::open_in_memory().unwrap();
        let session_a = sid(IdKind::Session, b"mixed-session-a");
        let session_b = sid(IdKind::Session, b"mixed-session-b");
        let document_a = sid(IdKind::Document, b"mixed-document-a");
        let document_b = sid(IdKind::Document, b"mixed-document-b");
        let parent_a = sid(IdKind::Message, b"mixed-parent-a");
        let parent_b = sid(IdKind::Message, b"mixed-parent-b");
        let child = sid(IdKind::Message, b"mixed-child");
        let placement_a = placement(&session_a, &document_a, &child, 1, false, Some((10, 20)));
        let placement_b = placement(&session_b, &document_b, &child, 2, true, Some((30, 40)));
        let source_a = |complete| {
            source_batch(
                "mixed-a.jsonl",
                vec![
                    (
                        child.clone(),
                        relational_message_payload(
                            &session_a,
                            &document_a,
                            &parent_a,
                            "native-parent-a",
                            false,
                            (10, 20),
                        ),
                        "shared stable body".into(),
                    ),
                    (
                        session_a.clone(),
                        session_payload(document_a.as_str(), &[child.as_str()]),
                        String::new(),
                    ),
                    entity_entry(&document_a),
                    entity_entry(&parent_a),
                ],
                vec![placement_a.clone()],
                vec![MessageEdge {
                    child_placement_id: placement_a.id.clone(),
                    parent_message_id: parent_a.clone(),
                    parent_native_id: Some("native-parent-a".into()),
                    relation: MessageRelation::Reply,
                }],
                complete,
            )
        };
        let source_b = source_batch(
            "mixed-b.jsonl",
            vec![
                (
                    child.clone(),
                    relational_message_payload(
                        &session_b,
                        &document_b,
                        &parent_b,
                        "native-parent-b",
                        true,
                        (30, 40),
                    ),
                    "shared stable body".into(),
                ),
                (
                    session_b.clone(),
                    session_payload(document_b.as_str(), &[child.as_str()]),
                    String::new(),
                ),
                entity_entry(&document_b),
                entity_entry(&parent_b),
            ],
            vec![placement_b.clone()],
            vec![MessageEdge {
                child_placement_id: placement_b.id.clone(),
                parent_message_id: parent_b.clone(),
                parent_native_id: Some("native-parent-b".into()),
                relation: MessageRelation::Reply,
            }],
            true,
        );

        store
            .commit_source_batches_if_changed(std::slice::from_ref(&source_a(false)))
            .unwrap();
        store
            .commit_source_batches_if_changed(std::slice::from_ref(&source_b))
            .unwrap();
        let mixed: serde_json::Value =
            serde_json::from_slice(&store.get(&child).unwrap().unwrap()).unwrap();
        assert_eq!(mixed["parent"], parent_a.as_str());
        assert_eq!(mixed["parent_native_id"], "native-parent-a");
        assert_eq!(mixed["is_sidechain"], false);

        assert!(
            store
                .commit_source_batches_if_changed(std::slice::from_ref(&source_a(true)))
                .unwrap()
        );
        let complete: serde_json::Value =
            serde_json::from_slice(&store.get(&child).unwrap().unwrap()).unwrap();
        assert_eq!(complete["parent"], serde_json::Value::Null);
        assert_eq!(complete["parent_native_id"], serde_json::Value::Null);
        assert_eq!(complete["is_sidechain"], serde_json::Value::Null);
        assert_eq!(complete["spans"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn context_graph_store_loads_typed_graph_and_groups_message_candidates_by_session() {
        let store = SqliteStore::open_in_memory().unwrap();
        let session = sid(IdKind::Session, b"typed-context-session");
        let document = sid(IdKind::Document, b"typed-context-document");
        let message = sid(IdKind::Message, b"typed-context-message");
        let first = placement(&session, &document, &message, 0, false, Some((0, 4)));
        let second = placement(&session, &document, &message, 1, true, Some((5, 9)));
        let source = source_batch(
            "typed-context.jsonl",
            vec![
                typed_message_entry(&message, "typed context body"),
                (
                    session.clone(),
                    session_payload(document.as_str(), &[message.as_str()]),
                    String::new(),
                ),
                typed_document_entry(&document),
            ],
            vec![first.clone(), second.clone()],
            Vec::new(),
            true,
        );
        store
            .commit_source_batches_if_changed(std::slice::from_ref(&source))
            .unwrap();

        let graph = store.load_session_graph(&session).unwrap();
        assert_eq!(graph.session_id, session);
        assert_eq!(graph.messages.len(), 1);
        assert_eq!(graph.messages[0].id, message);
        assert_eq!(graph.source_documents.len(), 1);
        assert_eq!(graph.source_documents[0].id, document);
        assert_eq!(graph.placements.len(), 2);
        assert!(graph.edges.is_empty());
        graph.validate().unwrap();

        let candidates = store.message_contexts(&message).unwrap();
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].session_id, session);
        assert_eq!(
            candidates[0].placement_ids,
            vec![first.id.clone(), second.id.clone()]
        );
        assert_eq!(
            store.context_stats().unwrap(),
            ContextStats {
                placements: 2,
                source_placement_claims: 2,
            }
        );
    }

    #[test]
    fn context_graph_store_keeps_zero_message_session_document_attribution() {
        let store = SqliteStore::open_in_memory().unwrap();
        let session = sid(IdKind::Session, b"zero-message-session");
        let document = sid(IdKind::Document, b"zero-message-document");
        let source = source_batch(
            "zero-message.jsonl",
            vec![
                (
                    session.clone(),
                    session_payload(document.as_str(), &[]),
                    String::new(),
                ),
                typed_document_entry(&document),
            ],
            Vec::new(),
            Vec::new(),
            true,
        );
        store
            .commit_source_batches_if_changed(std::slice::from_ref(&source))
            .unwrap();

        let graph = store.load_session_graph(&session).unwrap();
        assert!(graph.messages.is_empty());
        assert!(graph.placements.is_empty());
        assert!(graph.edges.is_empty());
        assert_eq!(graph.source_documents.len(), 1);
        assert_eq!(graph.source_documents[0].id, document);
        graph.validate().unwrap();
    }

    #[test]
    fn every_contributing_source_must_be_relation_complete_before_context_reads() {
        let store = SqliteStore::open_in_memory().unwrap();
        let session = sid(IdKind::Session, b"incomplete-context-session");
        let document_a = sid(IdKind::Document, b"complete-context-document");
        let document_b = sid(IdKind::Document, b"incomplete-context-document");
        let message_a = sid(IdKind::Message, b"complete-context-message");
        let message_b = sid(IdKind::Message, b"incomplete-context-message");
        let placement_a = placement(&session, &document_a, &message_a, 0, false, Some((0, 4)));
        let placement_b = placement(&session, &document_b, &message_b, 0, false, Some((0, 4)));
        let complete_source_path = "private-complete-source.jsonl";
        let incomplete_source_path = "private-incomplete-source.jsonl";
        let complete_source = source_batch(
            complete_source_path,
            vec![
                typed_message_entry(&message_a, "complete context body"),
                (
                    session.clone(),
                    session_payload(document_a.as_str(), &[message_a.as_str()]),
                    String::new(),
                ),
                typed_document_entry(&document_a),
            ],
            vec![placement_a],
            Vec::new(),
            true,
        );
        let incomplete_source = |complete| {
            source_batch(
                incomplete_source_path,
                vec![
                    typed_message_entry(&message_b, "incomplete context body"),
                    (
                        session.clone(),
                        session_payload(document_b.as_str(), &[message_b.as_str()]),
                        String::new(),
                    ),
                    typed_document_entry(&document_b),
                ],
                vec![placement_b.clone()],
                Vec::new(),
                complete,
            )
        };
        store
            .commit_source_batches_if_changed(&[complete_source, incomplete_source(false)])
            .unwrap();
        assert!(relation_complete_marker(&store, complete_source_path));
        assert!(!relation_complete_marker(&store, incomplete_source_path));

        let session_error = store.load_session_graph(&session).unwrap_err();
        assert!(
            matches!(&session_error, PortError::SchemaIncompatible(message) if message.contains("re-ingest required"))
        );
        assert!(!session_error.to_string().contains(complete_source_path));
        assert!(!session_error.to_string().contains(incomplete_source_path));

        let message_error = store.message_contexts(&message_b).unwrap_err();
        assert!(
            matches!(&message_error, PortError::SchemaIncompatible(message) if message.contains("re-ingest required"))
        );
        assert!(!message_error.to_string().contains(incomplete_source_path));

        assert!(
            store
                .commit_source_batches_if_changed(std::slice::from_ref(&incomplete_source(true)))
                .unwrap()
        );
        assert!(relation_complete_marker(&store, incomplete_source_path));

        let graph = store.load_session_graph(&session).unwrap();
        assert_eq!(graph.placements.len(), 2);
        assert!(
            graph
                .placements
                .iter()
                .any(|placement| placement.id == placement_b.id)
        );
        let contexts = store.message_contexts(&message_b).unwrap();
        assert_eq!(contexts.len(), 1);
        assert_eq!(contexts[0].session_id, session);
        assert_eq!(contexts[0].placement_ids, vec![placement_b.id.clone()]);
    }

    #[test]
    fn rebuild_preserves_relations_context_claims_and_completeness() {
        let store = SqliteStore::open_in_memory().unwrap();
        let session = sid(IdKind::Session, b"rebuild-context-session");
        let document = sid(IdKind::Document, b"rebuild-context-document");
        let parent = sid(IdKind::Message, b"rebuild-context-parent");
        let child = sid(IdKind::Message, b"rebuild-context-child");
        let parent_placement = placement(&session, &document, &parent, 0, false, Some((0, 4)));
        let child_placement = placement(&session, &document, &child, 1, false, Some((5, 9)));
        let source_path = "rebuild-context.jsonl";
        let source = source_batch(
            source_path,
            vec![
                typed_message_entry(&parent, "parent body"),
                typed_message_entry(&child, "child body"),
                (
                    session.clone(),
                    session_payload(document.as_str(), &[parent.as_str(), child.as_str()]),
                    String::new(),
                ),
                typed_document_entry(&document),
            ],
            vec![parent_placement, child_placement.clone()],
            vec![reply_edge(&child_placement, &parent)],
            true,
        );
        store
            .commit_source_batches_if_changed(std::slice::from_ref(&source))
            .unwrap();
        let graph_before = store.load_session_graph(&session).unwrap();
        let placements_before = store.stored_placements().unwrap();
        let edges_before = store.stored_edges().unwrap();
        let claims_before = source_placement_claims(&store, source_path);
        let stats_before = store.context_stats().unwrap();
        assert!(relation_complete_marker(&store, source_path));

        store.rebuild_index().unwrap();

        assert_eq!(store.load_session_graph(&session).unwrap(), graph_before);
        assert_eq!(store.stored_placements().unwrap(), placements_before);
        assert_eq!(store.stored_edges().unwrap(), edges_before);
        assert_eq!(source_placement_claims(&store, source_path), claims_before);
        assert_eq!(store.context_stats().unwrap(), stats_before);
        assert!(relation_complete_marker(&store, source_path));
    }

    #[test]
    fn load_session_graph_statement_count_is_bounded_regardless_of_edge_count() {
        // 上下文装配的 SQL 语句数只随 wire 批块增长,与边数无关(改前每条边
        // 一次父身份查询,N+1)。两个 1K+/2K+ 边的会话都应在常数界内,且
        // 语句数随边翻倍只增加批块差(≤12),不随边线性增长。
        let measure = |chain_len: usize, label: &str| -> (usize, usize) {
            let store = SqliteStore::open_in_memory().unwrap();
            let session = sid(IdKind::Session, format!("count-session-{label}").as_bytes());
            let document = sid(
                IdKind::Document,
                format!("count-document-{label}").as_bytes(),
            );
            let (source, _) =
                chain_source_batch(&format!("{label}.jsonl"), &session, &document, chain_len, 5);
            store
                .commit_source_batches_if_changed(std::slice::from_ref(&source))
                .unwrap();
            let edges = source.edges.len();
            let statements =
                counted_statements(&store, || store.load_session_graph(&session).unwrap());
            (statements, edges)
        };
        let (small_statements, small_edges) = measure(1200, "small");
        let (large_statements, large_edges) = measure(2400, "large");
        assert!(
            small_edges >= 1000,
            "fixture must exceed 1K edges, got {small_edges}"
        );
        assert!(
            small_statements <= 30,
            "small session ({small_edges} edges) issued {small_statements} statements; expected a constant bound independent of edge count"
        );
        assert!(
            large_statements <= 30,
            "large session ({large_edges} edges) issued {large_statements} statements; expected a constant bound independent of edge count"
        );
        assert!(
            large_statements <= small_statements + 12,
            "statement count must scale with wire chunks, not edges: {small_statements} -> {large_statements}"
        );
    }

    #[test]
    fn load_session_graph_keeps_orphan_parent_identity_grade() {
        // R1.2: 孤儿父(在本会话无出现、仅由边引用的消息)的身份必须经批量
        // fts_ids 加载保真,不能因批量路径缺 wire 而退化为 from_wire(Unstable)。
        let store = SqliteStore::open_in_memory().unwrap();
        let session = sid(IdKind::Session, b"grade-session");
        let document = sid(IdKind::Document, b"grade-document");
        let (source, orphans) = chain_source_batch("grade.jsonl", &session, &document, 20, 3);
        store
            .commit_source_batches_if_changed(std::slice::from_ref(&source))
            .unwrap();

        let graph = store.load_session_graph(&session).unwrap();
        // 边按 child_placement_id 排序,与孤儿索引顺序无关,按排序后的集合比较。
        let mut orphan_parents: Vec<&str> = graph
            .edges
            .iter()
            .filter(|edge| edge.parent_message_id.stability() == Stability::Native)
            .map(|edge| edge.parent_message_id.as_str())
            .collect();
        let mut expected: Vec<&str> = orphans.iter().map(|id| id.as_str()).collect();
        orphan_parents.sort();
        expected.sort();
        assert_eq!(
            orphan_parents, expected,
            "orphan parent identities must keep their Native grade and value"
        );
    }

    #[test]
    fn rebuild_index_statement_count_is_bounded_per_catalog_row() {
        // 读相从逐行 fts_ids 查询改为单条 LEFT JOIN:语句数相对改前恰好减少
        // catalog 行数。界取 2.5×rows:改后 ≈2×rows(读 1 + 写相每实体固定),
        // 改前 ≈3×rows(读相每行 1 条),回归会超出此界。
        let store = SqliteStore::open_in_memory().unwrap();
        let session = sid(IdKind::Session, b"rebuild-count-session");
        let document = sid(IdKind::Document, b"rebuild-count-document");
        let (source, _) = chain_source_batch("rebuild-count.jsonl", &session, &document, 1200, 5);
        store
            .commit_source_batches_if_changed(std::slice::from_ref(&source))
            .unwrap();
        let rows = table_count(&store, "catalog");
        assert!(
            rows > 1000,
            "fixture must exceed 1K catalog rows, got {rows}"
        );
        let statements = counted_statements(&store, || store.rebuild_index().unwrap());
        // 语句数含 FTS5 影子表维护,约 7×rows;改前逐行 fts_ids 身份读取还要再
        // 加 rows 条(≈8×rows),此界把逐行读回归挡在门外。
        assert!(
            statements as i64 <= rows * 7 + 600,
            "rebuild issued {statements} statements for {rows} catalog rows; expected <= {} (a per-row identity read would add ~{rows} more)",
            rows * 7 + 600
        );
    }

    #[test]
    fn incomplete_scan_updates_observed_relations_without_tombstoning_unseen_facts() {
        let store = SqliteStore::open_in_memory().unwrap();
        let session = sid(IdKind::Session, b"incomplete-update-session");
        let document = sid(IdKind::Document, b"incomplete-update-document");
        let parent_a = sid(IdKind::Message, b"incomplete-update-parent-a");
        let parent_b = sid(IdKind::Message, b"incomplete-update-parent-b");
        let observed_message = sid(IdKind::Message, b"incomplete-update-observed");
        let unseen_message = sid(IdKind::Message, b"incomplete-update-unseen");
        let original = placement(
            &session,
            &document,
            &observed_message,
            1,
            false,
            Some((1, 5)),
        );
        let changed = placement(
            &session,
            &document,
            &observed_message,
            1,
            true,
            Some((2, 6)),
        );
        let unseen = placement(
            &session,
            &document,
            &unseen_message,
            2,
            false,
            Some((7, 11)),
        );
        let entries = || {
            [
                &session,
                &document,
                &parent_a,
                &parent_b,
                &observed_message,
                &unseen_message,
            ]
            .into_iter()
            .map(entity_entry)
            .collect()
        };
        let initial = source_batch(
            "incomplete-update.jsonl",
            entries(),
            vec![original.clone(), unseen.clone()],
            vec![
                reply_edge(&original, &parent_a),
                reply_edge(&unseen, &parent_a),
            ],
            true,
        );
        store
            .commit_source_batches_if_changed(std::slice::from_ref(&initial))
            .unwrap();

        let changed_observation = source_batch(
            "incomplete-update.jsonl",
            entries(),
            vec![changed.clone()],
            vec![reply_edge(&changed, &parent_b)],
            false,
        );
        assert!(
            store
                .commit_source_batches_if_changed(std::slice::from_ref(&changed_observation))
                .unwrap()
        );
        assert!(
            store
                .stored_placements()
                .unwrap()
                .get(changed.id.as_str())
                .unwrap()
                .matches(&changed)
        );
        assert!(
            store
                .stored_edges()
                .unwrap()
                .get(changed.id.as_str())
                .unwrap()
                .matches(&reply_edge(&changed, &parent_b))
        );
        assert!(
            store
                .stored_placements()
                .unwrap()
                .contains_key(unseen.id.as_str())
        );
        assert!(
            store
                .stored_edges()
                .unwrap()
                .contains_key(unseen.id.as_str())
        );
        assert!(!relation_complete_marker(&store, "incomplete-update.jsonl"));

        let observed_root = source_batch(
            "incomplete-update.jsonl",
            entries(),
            vec![changed.clone()],
            Vec::new(),
            false,
        );
        assert!(
            store
                .commit_source_batches_if_changed(std::slice::from_ref(&observed_root))
                .unwrap()
        );
        assert!(
            !store
                .stored_edges()
                .unwrap()
                .contains_key(changed.id.as_str())
        );
        assert!(
            store
                .stored_edges()
                .unwrap()
                .contains_key(unseen.id.as_str())
        );
    }

    #[test]
    fn incomplete_scan_unions_claims_and_complete_scan_replaces_with_tombstones() {
        let store = SqliteStore::open_in_memory().unwrap();
        let session = sid(IdKind::Session, b"replacement-session");
        let document = sid(IdKind::Document, b"replacement-document");
        let parent = sid(IdKind::Message, b"replacement-parent");
        let old_message = sid(IdKind::Message, b"replacement-old");
        let new_message = sid(IdKind::Message, b"replacement-new");
        let old_placement = placement(&session, &document, &old_message, 1, false, Some((1, 5)));
        let new_placement = placement(&session, &document, &new_message, 2, false, Some((6, 10)));

        let initial = source_batch(
            "replacement.jsonl",
            [&session, &document, &parent, &old_message]
                .into_iter()
                .map(entity_entry)
                .collect(),
            vec![old_placement.clone()],
            vec![reply_edge(&old_placement, &parent)],
            true,
        );
        store
            .commit_source_batches_if_changed(std::slice::from_ref(&initial))
            .unwrap();

        let incomplete = source_batch(
            "replacement.jsonl",
            [&session, &document, &parent, &new_message]
                .into_iter()
                .map(entity_entry)
                .collect(),
            vec![new_placement.clone()],
            vec![reply_edge(&new_placement, &parent)],
            false,
        );
        assert!(
            store
                .commit_source_batches_if_changed(std::slice::from_ref(&incomplete))
                .unwrap()
        );
        assert!(store.get(&old_message).unwrap().is_some());
        assert!(store.get(&new_message).unwrap().is_some());
        assert!(
            store
                .stored_placements()
                .unwrap()
                .contains_key(old_placement.id.as_str())
        );
        assert!(
            store
                .stored_edges()
                .unwrap()
                .contains_key(old_placement.id.as_str())
        );
        let expected_claims: Vec<_> = [
            old_placement.id.as_str().to_string(),
            new_placement.id.as_str().to_string(),
        ]
        .into_iter()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
        assert_eq!(
            source_placement_claims(&store, "replacement.jsonl"),
            expected_claims
        );
        assert!(!relation_complete_marker(&store, "replacement.jsonl"));

        let complete = source_batch(
            "replacement.jsonl",
            [&session, &document, &parent, &new_message]
                .into_iter()
                .map(entity_entry)
                .collect(),
            vec![new_placement.clone()],
            vec![reply_edge(&new_placement, &parent)],
            true,
        );
        assert!(
            store
                .commit_source_batches_if_changed(std::slice::from_ref(&complete))
                .unwrap()
        );
        assert!(store.get(&old_message).unwrap().is_none());
        assert!(store.get(&new_message).unwrap().is_some());
        assert!(
            !store
                .stored_placements()
                .unwrap()
                .contains_key(old_placement.id.as_str())
        );
        assert!(
            !store
                .stored_edges()
                .unwrap()
                .contains_key(old_placement.id.as_str())
        );
        assert_eq!(
            source_placement_claims(&store, "replacement.jsonl"),
            vec![new_placement.id.as_str().to_string()]
        );
        assert!(relation_complete_marker(&store, "replacement.jsonl"));
    }

    #[test]
    fn complete_empty_replacement_preserves_shared_facts_then_tombstones_last_claim() {
        let store = SqliteStore::open_in_memory().unwrap();
        let session = sid(IdKind::Session, b"shared-survival-session");
        let document = sid(IdKind::Document, b"shared-survival-document");
        let parent = sid(IdKind::Message, b"shared-survival-parent");
        let child = sid(IdKind::Message, b"shared-survival-child");
        let child_placement = placement(&session, &document, &child, 1, false, Some((2, 8)));
        let entries = || {
            [&session, &document, &parent, &child]
                .into_iter()
                .map(entity_entry)
                .collect()
        };
        let edge = reply_edge(&child_placement, &parent);
        let sources = [
            source_batch(
                "shared-a.jsonl",
                entries(),
                vec![child_placement.clone()],
                vec![edge.clone()],
                true,
            ),
            source_batch(
                "shared-b.jsonl",
                entries(),
                vec![child_placement.clone()],
                vec![edge],
                true,
            ),
        ];
        store.commit_source_batches_if_changed(&sources).unwrap();

        let empty_a = source_batch("shared-a.jsonl", Vec::new(), Vec::new(), Vec::new(), true);
        assert!(
            store
                .commit_source_batches_if_changed(std::slice::from_ref(&empty_a))
                .unwrap()
        );
        assert!(store.get(&child).unwrap().is_some());
        assert!(
            store
                .stored_placements()
                .unwrap()
                .contains_key(child_placement.id.as_str())
        );
        assert!(
            store
                .stored_edges()
                .unwrap()
                .contains_key(child_placement.id.as_str())
        );
        assert!(source_placement_claims(&store, "shared-a.jsonl").is_empty());
        assert_eq!(
            source_placement_claims(&store, "shared-b.jsonl"),
            vec![child_placement.id.as_str().to_string()]
        );
        let empty_manifest = latest_index_batch(&store).source_replacements.remove(0);
        assert_eq!(empty_manifest["source_path"], "shared-a.jsonl");
        assert_eq!(empty_manifest["entity_memberships"], serde_json::json!([]));
        assert_eq!(empty_manifest["placement_ids"], serde_json::json!([]));
        assert_eq!(empty_manifest["relation_complete"], true);

        let generation = store.active_generation().unwrap();
        assert!(
            !store
                .commit_source_batches_if_changed(std::slice::from_ref(&empty_a))
                .unwrap()
        );
        assert_eq!(store.active_generation().unwrap(), generation);

        let empty_b = source_batch("shared-b.jsonl", Vec::new(), Vec::new(), Vec::new(), true);
        assert!(
            store
                .commit_source_batches_if_changed(std::slice::from_ref(&empty_b))
                .unwrap()
        );
        assert!(store.get(&child).unwrap().is_none());
        assert!(
            !store
                .stored_placements()
                .unwrap()
                .contains_key(child_placement.id.as_str())
        );
        assert!(
            !store
                .stored_edges()
                .unwrap()
                .contains_key(child_placement.id.as_str())
        );
    }

    #[test]
    fn shared_relation_change_requires_all_claimants_in_one_complete_batch() {
        let store = SqliteStore::open_in_memory().unwrap();
        let session = sid(IdKind::Session, b"shared-change-session");
        let document = sid(IdKind::Document, b"shared-change-document");
        let parent_a = sid(IdKind::Message, b"shared-change-parent-a");
        let parent_b = sid(IdKind::Message, b"shared-change-parent-b");
        let child = sid(IdKind::Message, b"shared-change-child");
        let original = placement(&session, &document, &child, 1, false, Some((10, 20)));
        let changed = placement(&session, &document, &child, 1, true, Some((11, 21)));
        assert_eq!(original.id, changed.id);
        let entries = || {
            [&session, &document, &parent_a, &parent_b, &child]
                .into_iter()
                .map(entity_entry)
                .collect()
        };
        let initial = [
            source_batch(
                "change-a.jsonl",
                entries(),
                vec![original.clone()],
                vec![reply_edge(&original, &parent_a)],
                true,
            ),
            source_batch(
                "change-b.jsonl",
                entries(),
                vec![original.clone()],
                vec![reply_edge(&original, &parent_a)],
                true,
            ),
        ];
        store.commit_source_batches_if_changed(&initial).unwrap();
        let generation = store.active_generation().unwrap();

        let only_a = source_batch(
            "change-a.jsonl",
            entries(),
            vec![changed.clone()],
            vec![reply_edge(&changed, &parent_a)],
            true,
        );
        let err = store
            .commit_source_batches_if_changed(std::slice::from_ref(&only_a))
            .unwrap_err();
        assert!(
            matches!(err, PortError::Backend(message) if message.contains("did not observe the same placement"))
        );
        assert_eq!(store.active_generation().unwrap(), generation);
        assert!(
            store
                .stored_placements()
                .unwrap()
                .get(original.id.as_str())
                .unwrap()
                .matches(&original)
        );

        let changed_both = [
            source_batch(
                "change-a.jsonl",
                entries(),
                vec![changed.clone()],
                vec![reply_edge(&changed, &parent_b)],
                true,
            ),
            source_batch(
                "change-b.jsonl",
                entries(),
                vec![changed.clone()],
                vec![reply_edge(&changed, &parent_b)],
                true,
            ),
        ];
        assert!(
            store
                .commit_source_batches_if_changed(&changed_both)
                .unwrap()
        );
        assert_eq!(store.active_generation().unwrap(), generation + 1);
        assert!(
            store
                .stored_placements()
                .unwrap()
                .get(changed.id.as_str())
                .unwrap()
                .matches(&changed)
        );
        assert!(
            store
                .stored_edges()
                .unwrap()
                .get(changed.id.as_str())
                .unwrap()
                .matches(&reply_edge(&changed, &parent_b))
        );
    }

    #[test]
    fn edge_only_change_requires_every_shared_claimant_to_observe_the_new_edge() {
        let store = SqliteStore::open_in_memory().unwrap();
        let session = sid(IdKind::Session, b"shared-edge-session");
        let document = sid(IdKind::Document, b"shared-edge-document");
        let parent_a = sid(IdKind::Message, b"shared-edge-parent-a");
        let parent_b = sid(IdKind::Message, b"shared-edge-parent-b");
        let child = sid(IdKind::Message, b"shared-edge-child");
        let child_placement = placement(&session, &document, &child, 1, false, Some((3, 9)));
        let entries = || {
            [&session, &document, &parent_a, &parent_b, &child]
                .into_iter()
                .map(entity_entry)
                .collect()
        };
        let initial = [
            source_batch(
                "shared-edge-a.jsonl",
                entries(),
                vec![child_placement.clone()],
                vec![reply_edge(&child_placement, &parent_a)],
                true,
            ),
            source_batch(
                "shared-edge-b.jsonl",
                entries(),
                vec![child_placement.clone()],
                vec![reply_edge(&child_placement, &parent_a)],
                true,
            ),
        ];
        store.commit_source_batches_if_changed(&initial).unwrap();
        let generation = store.active_generation().unwrap();

        let only_a = source_batch(
            "shared-edge-a.jsonl",
            entries(),
            vec![child_placement.clone()],
            vec![reply_edge(&child_placement, &parent_b)],
            true,
        );
        let err = store
            .commit_source_batches_if_changed(std::slice::from_ref(&only_a))
            .unwrap_err();
        assert!(
            matches!(err, PortError::Backend(message) if message.contains("did not observe the same edge"))
        );
        assert_eq!(store.active_generation().unwrap(), generation);
        assert!(
            store
                .stored_edges()
                .unwrap()
                .get(child_placement.id.as_str())
                .unwrap()
                .matches(&reply_edge(&child_placement, &parent_a))
        );

        let changed_both = [
            source_batch(
                "shared-edge-a.jsonl",
                entries(),
                vec![child_placement.clone()],
                vec![reply_edge(&child_placement, &parent_b)],
                true,
            ),
            source_batch(
                "shared-edge-b.jsonl",
                entries(),
                vec![child_placement.clone()],
                vec![reply_edge(&child_placement, &parent_b)],
                true,
            ),
        ];
        assert!(
            store
                .commit_source_batches_if_changed(&changed_both)
                .unwrap()
        );
        assert!(
            store
                .stored_edges()
                .unwrap()
                .get(child_placement.id.as_str())
                .unwrap()
                .matches(&reply_edge(&child_placement, &parent_b))
        );
    }

    #[test]
    fn relation_apply_failure_rolls_back_everything_except_building_intent() {
        let store = SqliteStore::open_in_memory().unwrap();
        store
            .conn
            .borrow()
            .execute_batch(
                "CREATE TRIGGER fail_relation_insert
                 BEFORE INSERT ON message_placements
                 BEGIN
                     SELECT RAISE(ABORT, 'injected relation failure');
                 END;",
            )
            .unwrap();
        let session = sid(IdKind::Session, b"rollback-session");
        let document = sid(IdKind::Document, b"rollback-document");
        let message = sid(IdKind::Message, b"rollback-message");
        let message_placement = placement(&session, &document, &message, 0, false, Some((0, 4)));
        let source = source_batch(
            "rollback.jsonl",
            [&session, &document, &message]
                .into_iter()
                .map(entity_entry)
                .collect(),
            vec![message_placement],
            Vec::new(),
            true,
        );

        let err = store
            .commit_source_batches_if_changed(std::slice::from_ref(&source))
            .unwrap_err();
        assert!(matches!(err, PortError::Backend(_)));
        assert_eq!(store.active_generation().unwrap(), 0);
        for table in [
            "catalog",
            "fts",
            "fts_ids",
            "source_membership",
            "source_scans",
            "message_placements",
            "message_edges",
            "source_placement_membership",
            "source_relation_scans",
        ] {
            assert_eq!(table_count(&store, table), 0, "{table} must roll back");
        }
        let batch = latest_index_batch(&store);
        assert_eq!(batch.state, "building");
        assert_eq!(batch.durable_point, "intent");
    }

    #[test]
    fn deleting_by_wire_id_removes_search_row() {
        let store = SqliteStore::open_in_memory().unwrap();
        let original = sid(IdKind::Message, b"wire-delete");
        store.index(&original, "wire deletion text").unwrap();
        let wire_id = StableId::from_wire(original.as_str()).unwrap();
        let entries: [(StableId, Vec<u8>, String); 0] = [];
        let pending = store
            .begin_index_batch(&entries, std::slice::from_ref(&wire_id))
            .unwrap();
        store
            .commit_index_batch(&pending, &entries, &[wire_id])
            .unwrap();
        assert_eq!(store.count().unwrap(), 0);
        assert!(store.query("deletion", 10).unwrap().is_empty());
    }

    #[test]
    fn standalone_index_populates_wire_mapping() {
        let store = SqliteStore::open_in_memory().unwrap();
        let original = sid(IdKind::Message, b"standalone-map");
        store.index(&original, "standalone mapping text").unwrap();
        let wire_id = StableId::from_wire(original.as_str()).unwrap();
        let entries: [(StableId, Vec<u8>, String); 0] = [];
        let pending = store
            .begin_index_batch(&entries, std::slice::from_ref(&wire_id))
            .unwrap();
        store
            .commit_index_batch(&pending, &entries, &[wire_id])
            .unwrap();
        assert!(store.query("mapping", 10).unwrap().is_empty());
    }

    #[test]
    fn fts_rowids_track_rows_across_commit_rebuild_and_delete() {
        // 回归：fts5 的 id 列是内容列不是 rowid；fts_ids.fts_rowid 边车必须与
        // fts 行一一对应，且对批量提交、rebuild、按 wire 别名删除保持一致。
        let store = SqliteStore::open_in_memory().unwrap();
        let messages: Vec<StableId> = (0..50)
            .map(|i| sid(IdKind::Message, format!("rowid-{i}").as_bytes()))
            .collect();
        let ses = sid(IdKind::Session, b"rowid-container");
        let source = SourceBatch {
            source_path: "rowid.jsonl".into(),
            placements: Vec::new(),
            edges: Vec::new(),
            activities: Vec::new(),
            relation_complete: true,
            len_bytes: None,
            fingerprint: None,
            provider_id: None,
            resume_claim: None,
            entries: messages
                .iter()
                .enumerate()
                // payload 需与 text 在 rebuild 重投影下 round-trip：rebuild 从
                // catalog 经 searchable_text 重新提取正文（'\t' 前是 role），
                // 若 payload 不携带正文，rebuild 后 fts 行将不再可搜。
                .map(|(i, id)| {
                    (
                        id.clone(),
                        format!("user\trowid text {i}").into_bytes(),
                        format!("rowid text {i}"),
                    )
                })
                .chain(std::iter::once((ses.clone(), b"s".to_vec(), String::new())))
                .collect(),
        };
        assert!(
            store
                .commit_source_batches_if_changed(std::slice::from_ref(&source))
                .unwrap()
        );
        let conn = store.conn.borrow();
        let mismatch: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM fts f
                 JOIN fts_ids fi ON fi.id_json = f.id
                 WHERE fi.fts_rowid IS NULL OR fi.fts_rowid != f.rowid",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            mismatch, 0,
            "every fts row must carry its rowid in the sidecar"
        );
        let fts_rows: i64 = conn
            .query_row("SELECT COUNT(*) FROM fts", [], |row| row.get(0))
            .unwrap();
        assert_eq!(fts_rows, 50);
        let session_rid: Option<i64> = conn
            .query_row(
                "SELECT fts_rowid FROM fts_ids WHERE wire_id = ?1",
                [ses.as_str()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(session_rid, None, "non-message sidecar rows stay NULL");
        drop(conn);

        // rebuild 整表清空重投影后映射仍然成立。
        store.rebuild_index().unwrap();
        let conn = store.conn.borrow();
        let mismatch: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM fts f
                 JOIN fts_ids fi ON fi.id_json = f.id
                 WHERE fi.fts_rowid IS NULL OR fi.fts_rowid != f.rowid",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(mismatch, 0, "rebuild must restore the rowid sidecar");
        drop(conn);

        // 按 wire 别名（from_wire 降级为 Unstable）删除仍能定位到 fts 行。
        let victim = messages[17].clone();
        let wire_id = StableId::from_wire(victim.as_str()).unwrap();
        let entries: [(StableId, Vec<u8>, String); 0] = [];
        let pending = store
            .begin_index_batch(&entries, std::slice::from_ref(&wire_id))
            .unwrap();
        store
            .commit_index_batch(&pending, &entries, &[wire_id])
            .unwrap();
        assert!(
            store.query("rowid text 17", 10).unwrap().is_empty(),
            "alias delete must remove the fts row"
        );
        assert_eq!(store.query("rowid text 16", 10).unwrap().len(), 1);
        assert_eq!(store.count().unwrap(), 50);
    }

    #[test]
    fn large_store_delete_is_rowid_scoped_not_content_scanned() {
        // 回归（性能护栏）：10K 消息库上删除单条。旧实现按内容列 id 比较，
        // 每次删除整表扫描 fts（10K 行约 6.3s）；新实现经 fts_ids.fts_rowid
        // 按 rowid 定位（µs 级）。3s 宽限只拦内容扫描回归，对 rowid 路径有
        // 数个数量级的余量，不依赖计时精度。
        let store = SqliteStore::open_in_memory().unwrap();
        let messages: Vec<StableId> = (0..10_000)
            .map(|i| sid(IdKind::Message, format!("bulk-{i}").as_bytes()))
            .collect();
        let source = SourceBatch {
            source_path: "bulk.jsonl".into(),
            placements: Vec::new(),
            edges: Vec::new(),
            activities: Vec::new(),
            relation_complete: true,
            len_bytes: None,
            fingerprint: None,
            provider_id: None,
            resume_claim: None,
            entries: messages
                .iter()
                .enumerate()
                .map(|(i, id)| (id.clone(), b"m".to_vec(), format!("bulk text {i}")))
                .collect(),
        };
        assert!(
            store
                .commit_source_batches_if_changed(std::slice::from_ref(&source))
                .unwrap()
        );
        assert_eq!(store.query("bulk text 5000", 10).unwrap().len(), 1);
        let victim = messages[5000].clone();
        let entries: [(StableId, Vec<u8>, String); 0] = [];
        let pending = store
            .begin_index_batch(&entries, std::slice::from_ref(&victim))
            .unwrap();
        let started = std::time::Instant::now();
        store
            .commit_index_batch(&pending, &entries, &[victim])
            .unwrap();
        let elapsed = started.elapsed();
        assert!(
            elapsed < std::time::Duration::from_secs(3),
            "delete must not scan the fts table: {elapsed:?}"
        );
        assert!(store.query("bulk text 5000", 10).unwrap().is_empty());
        assert_eq!(store.query("bulk text 4999", 10).unwrap().len(), 1);
    }

    #[test]
    fn v7_open_backfills_fts_rowid_for_legacy_rows() {
        // 旧 v7 库（fts_rowid 列加入前建成）首次打开必须回填边车：fts 行按
        // id_json 与 fts_ids 一一对应，回填后按 wire 别名删除才能按 rowid 定位。
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("legacy-fts.db");
        let p = path.to_string_lossy().into_owned();
        let legacy = sid(IdKind::Message, b"legacy-fts-row");
        let legacy_json = serde_json::to_string(&legacy).unwrap();
        {
            let conn = rusqlite::Connection::open(&p).unwrap();
            create_v6_schema(&conn);
            // 旧式 fts/fts_ids：fts 行由 fts5 自动分配 rowid，边车没有 rowid
            // 概念；随后 open 会走 v6→v7 + 本列一次性回填。
            conn.execute(
                "INSERT INTO catalog(id, payload) VALUES(?1, ?2)",
                rusqlite::params![legacy.as_str(), b"legacy".to_vec()],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO fts(id, text) VALUES(?1, ?2)",
                rusqlite::params![legacy_json, "legacy fts body"],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO fts_ids(wire_id, id_json) VALUES(?1, ?2)",
                rusqlite::params![legacy.as_str(), legacy_json],
            )
            .unwrap();
            // 容器实体：无 fts 行，回填后 fts_rowid 必须保持 NULL。
            conn.execute(
                "INSERT INTO fts_ids(wire_id, id_json) VALUES(?1, ?2)",
                rusqlite::params![
                    "legacy-session",
                    serde_json::to_string(&sid(IdKind::Session, b"legacy-session")).unwrap()
                ],
            )
            .unwrap();
        }
        let store = SqliteStore::open(&p).unwrap();
        let conn = store.conn.borrow();
        let mismatch: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM fts f
                 JOIN fts_ids fi ON fi.id_json = f.id
                 WHERE fi.fts_rowid IS NULL OR fi.fts_rowid != f.rowid",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(mismatch, 0, "legacy fts rows must be backfilled on open");
        let session_rid: Option<i64> = conn
            .query_row(
                "SELECT fts_rowid FROM fts_ids WHERE wire_id = 'legacy-session'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(session_rid, None);
        drop(conn);

        // 回填后按 wire 别名删除能定位到旧 fts 行（无 fts 残留）。
        let wire_id = StableId::from_wire(legacy.as_str()).unwrap();
        let entries: [(StableId, Vec<u8>, String); 0] = [];
        let pending = store
            .begin_index_batch(&entries, std::slice::from_ref(&wire_id))
            .unwrap();
        store
            .commit_index_batch(&pending, &entries, &[wire_id])
            .unwrap();
        assert!(store.query("legacy fts body", 10).unwrap().is_empty());
        assert_eq!(store.count().unwrap(), 0);
    }

    #[test]
    fn source_rescan_tombstones_removed_messages() {
        let store = SqliteStore::open_in_memory().unwrap();
        let a = sid(IdKind::Message, b"source-a");
        let b = sid(IdKind::Message, b"source-b");
        let first = SourceBatch {
            source_path: "fixture.jsonl".into(),
            placements: Vec::new(),
            edges: Vec::new(),
            activities: Vec::new(),
            relation_complete: true,
            len_bytes: None,
            fingerprint: None,
            provider_id: None,
            resume_claim: None,
            entries: vec![
                (a.clone(), b"a".to_vec(), "keep alpha".into()),
                (b.clone(), b"b".to_vec(), "remove beta".into()),
            ],
        };
        assert!(
            store
                .commit_source_batches_if_changed(std::slice::from_ref(&first))
                .unwrap()
        );
        assert_eq!(store.count().unwrap(), 2);
        assert_eq!(store.query("beta", 10).unwrap().len(), 1);

        let second = SourceBatch {
            source_path: "fixture.jsonl".into(),
            placements: Vec::new(),
            edges: Vec::new(),
            activities: Vec::new(),
            relation_complete: true,
            len_bytes: None,
            fingerprint: None,
            provider_id: None,
            resume_claim: None,
            entries: vec![(a.clone(), b"a".to_vec(), "keep alpha".into())],
        };
        assert!(
            store
                .commit_source_batches_if_changed(std::slice::from_ref(&second))
                .unwrap()
        );
        assert_eq!(store.count().unwrap(), 1);
        assert!(store.get(&b).unwrap().is_none());
        assert!(store.query("beta", 10).unwrap().is_empty());
        assert_eq!(store.query("alpha", 10).unwrap().len(), 1);
    }

    #[test]
    fn unchanged_source_rescan_does_not_advance_generation() {
        let store = SqliteStore::open_in_memory().unwrap();
        let a = sid(IdKind::Message, b"same-source");
        let source = SourceBatch {
            source_path: "same.jsonl".into(),
            placements: Vec::new(),
            edges: Vec::new(),
            activities: Vec::new(),
            relation_complete: true,
            len_bytes: None,
            fingerprint: None,
            provider_id: None,
            resume_claim: None,
            entries: vec![(a, b"payload".to_vec(), "same text".into())],
        };
        assert!(
            store
                .commit_source_batches_if_changed(std::slice::from_ref(&source))
                .unwrap()
        );
        assert_eq!(store.active_generation().unwrap(), 1);
        assert!(
            !store
                .commit_source_batches_if_changed(std::slice::from_ref(&source))
                .unwrap()
        );
        assert_eq!(store.active_generation().unwrap(), 1);
    }

    #[test]
    fn v3_db_migrates_source_membership_table() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v3.db");
        let p = path.to_string_lossy().into_owned();
        {
            let conn = rusqlite::Connection::open(&p).unwrap();
            conn.execute_batch(
                "CREATE TABLE catalog (id TEXT PRIMARY KEY, payload BLOB NOT NULL);
                 CREATE VIRTUAL TABLE fts USING fts5(id UNINDEXED, text);
                 CREATE TABLE store_metadata (singleton INTEGER PRIMARY KEY CHECK(singleton = 1), active_generation INTEGER NOT NULL);
                 INSERT INTO store_metadata(singleton, active_generation) VALUES(1, 0);
                 CREATE TABLE index_batches (
                     operation_id TEXT PRIMARY KEY, base_generation INTEGER NOT NULL,
                     target_generation INTEGER NOT NULL, state TEXT NOT NULL,
                     operation_digest TEXT NOT NULL, upsert_ids_json TEXT NOT NULL,
                     delete_ids_json TEXT NOT NULL, durable_point TEXT NOT NULL,
                     created_at_ms INTEGER NOT NULL, committed_at_ms INTEGER,
                     error_code TEXT
                 );
                 CREATE TABLE fts_ids (wire_id TEXT PRIMARY KEY, id_json TEXT NOT NULL UNIQUE);
                 PRAGMA user_version = 3;",
            )
            .unwrap();
        }
        let store = SqliteStore::open(&p).unwrap();
        assert_eq!(store.schema_version().unwrap(), SCHEMA_VERSION);
        let conn = rusqlite::Connection::open(&p).unwrap();
        let exists: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'source_membership'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(exists, 1);
        drop(store);
    }

    #[test]
    fn v5_db_migrates_membership_document_id_column() {
        // 带数据的 v5 库升级到 v6：membership 旧行保留且 document_id 为 NULL。
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v5.db");
        let p = path.to_string_lossy().into_owned();
        {
            let conn = rusqlite::Connection::open(&p).unwrap();
            conn.execute_batch(
                "CREATE TABLE catalog (id TEXT PRIMARY KEY, payload BLOB NOT NULL);
                 CREATE VIRTUAL TABLE fts USING fts5(id UNINDEXED, text);
                 CREATE TABLE store_metadata (singleton INTEGER PRIMARY KEY CHECK(singleton = 1), active_generation INTEGER NOT NULL);
                 INSERT INTO store_metadata(singleton, active_generation) VALUES(1, 1);
                 CREATE TABLE index_batches (
                     operation_id TEXT PRIMARY KEY, base_generation INTEGER NOT NULL,
                     target_generation INTEGER NOT NULL, state TEXT NOT NULL,
                     operation_digest TEXT NOT NULL, upsert_ids_json TEXT NOT NULL,
                     delete_ids_json TEXT NOT NULL, durable_point TEXT NOT NULL,
                     created_at_ms INTEGER NOT NULL, committed_at_ms INTEGER,
                     error_code TEXT
                 );
                 CREATE TABLE fts_ids (wire_id TEXT PRIMARY KEY, id_json TEXT NOT NULL UNIQUE);
                 CREATE TABLE source_membership (
                     source_path TEXT NOT NULL,
                     message_id  TEXT NOT NULL,
                     PRIMARY KEY(source_path, message_id)
                 );
                 CREATE TABLE source_scans (
                     source_path   TEXT PRIMARY KEY,
                     scanned_at_ms INTEGER NOT NULL
                 );
                 INSERT INTO catalog(id, payload) VALUES('msg_v1_legacy', X'01');
                 INSERT INTO source_membership(source_path, message_id)
                 VALUES('legacy.jsonl', 'msg_v1_legacy');
                 INSERT INTO source_scans(source_path, scanned_at_ms) VALUES('legacy.jsonl', 1);
                 PRAGMA user_version = 5;",
            )
            .unwrap();
        }
        let store = SqliteStore::open(&p).unwrap();
        assert_eq!(store.schema_version().unwrap(), SCHEMA_VERSION);
        // 旧数据完整保留。
        let id = StableId::from_wire("msg_v1_legacy").unwrap();
        assert_eq!(store.get(&id).unwrap().unwrap(), vec![1u8]);
        drop(store);
        let conn = rusqlite::Connection::open(&p).unwrap();
        let doc: Option<String> = conn
            .query_row(
                "SELECT document_id FROM source_membership WHERE message_id = 'msg_v1_legacy'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        // v6 前的 membership 行无文档归属信息——显式 NULL，不臆造。
        assert_eq!(doc, None);
    }

    #[test]
    fn non_message_entities_are_catalog_only() {
        // session/document 实体入 catalog、可 get/list，但绝不进入全文搜索。
        let store = SqliteStore::open_in_memory().unwrap();
        let msg = sid(IdKind::Message, b"cat-only-msg");
        let ses = sid(IdKind::Session, b"cat-only-ses");
        let doc = sid(IdKind::Document, b"cat-only-doc");
        let source = SourceBatch {
            source_path: "mixed.jsonl".into(),
            placements: Vec::new(),
            edges: Vec::new(),
            activities: Vec::new(),
            relation_complete: true,
            len_bytes: None,
            fingerprint: None,
            provider_id: None,
            resume_claim: None,
            entries: vec![
                (msg.clone(), b"m".to_vec(), "unique searchable body".into()),
                (ses.clone(), b"s".to_vec(), "unique searchable body".into()),
                (doc.clone(), b"d".to_vec(), "unique searchable body".into()),
            ],
        };
        assert!(
            store
                .commit_source_batches_if_changed(std::slice::from_ref(&source))
                .unwrap()
        );
        // catalog 三个实体都在。
        assert_eq!(store.count().unwrap(), 3);
        assert!(store.get(&ses).unwrap().is_some());
        assert!(store.get(&doc).unwrap().is_some());
        // 搜索只命中消息——容器实体不参与全文命中，避免重复计数。
        let hits = store.query("searchable", 10).unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].id.as_str(), msg.as_str());
        // fts_ids 身份边车对所有 kind 保留（rebuild 依赖它保真身份）。
        let conn = store.conn.borrow();
        let sidecar: i64 = conn
            .query_row("SELECT COUNT(*) FROM fts_ids", [], |row| row.get(0))
            .unwrap();
        assert_eq!(sidecar, 3);
        // 重复提交同一批是内容级 no-op（非消息实体不因缺 fts 行而误判为变更）。
        drop(conn);
        assert!(
            !store
                .commit_source_batches_if_changed(std::slice::from_ref(&source))
                .unwrap()
        );
    }

    #[test]
    fn rebuild_keeps_non_message_entities_out_of_fts() {
        // 混合库 rebuild：身份保真、消息重投影、容器实体仍不进 fts。
        let store = SqliteStore::open_in_memory().unwrap();
        let msg = sid(IdKind::Message, b"rebuild-msg");
        let ses = sid(IdKind::Session, b"rebuild-ses");
        let source = SourceBatch {
            source_path: "rebuild.jsonl".into(),
            placements: Vec::new(),
            edges: Vec::new(),
            activities: Vec::new(),
            relation_complete: true,
            len_bytes: None,
            fingerprint: None,
            provider_id: None,
            resume_claim: None,
            entries: vec![
                (
                    msg.clone(),
                    b"role\tbody words".to_vec(),
                    "body words".into(),
                ),
                (ses.clone(), b"s".to_vec(), String::new()),
            ],
        };
        store
            .commit_source_batches_if_changed(std::slice::from_ref(&source))
            .unwrap();
        let rebuilt = store.rebuild_index().unwrap();
        assert_eq!(rebuilt, 2);
        // 消息可搜、身份保真（非 Unstable——来自 fts_ids 边车）。
        let hits = store.query("body", 10).unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].id.stability(), Stability::Reconstructed);
        // 容器实体：无 fts 行、有 fts_ids 边车。
        let conn = store.conn.borrow();
        let fts_rows: i64 = conn
            .query_row("SELECT COUNT(*) FROM fts", [], |row| row.get(0))
            .unwrap();
        assert_eq!(fts_rows, 1);
        let sidecar: i64 = conn
            .query_row("SELECT COUNT(*) FROM fts_ids", [], |row| row.get(0))
            .unwrap();
        assert_eq!(sidecar, 2);
    }

    #[test]
    fn source_rescan_retires_session_and_document_rows() {
        // 源缩水成空 scan：其 session/document 目录行随消息一起 tombstone。
        let store = SqliteStore::open_in_memory().unwrap();
        let msg = sid(IdKind::Message, b"retire-msg");
        let ses = sid(IdKind::Session, b"retire-ses");
        let doc = sid(IdKind::Document, b"retire-doc");
        let full = SourceBatch {
            source_path: "retire.jsonl".into(),
            placements: Vec::new(),
            edges: Vec::new(),
            activities: Vec::new(),
            relation_complete: true,
            len_bytes: None,
            fingerprint: None,
            provider_id: None,
            resume_claim: None,
            entries: vec![
                (msg.clone(), b"m".to_vec(), "text".into()),
                (ses.clone(), b"s".to_vec(), String::new()),
                (doc.clone(), b"d".to_vec(), String::new()),
            ],
        };
        store
            .commit_source_batches_if_changed(std::slice::from_ref(&full))
            .unwrap();
        // membership 记录了该源的文档归属。
        {
            let conn = store.conn.borrow();
            let recorded: Option<String> = conn
                .query_row(
                    "SELECT document_id FROM source_membership WHERE message_id = ?1",
                    [msg.as_str()],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(recorded.as_deref(), Some(doc.as_str()));
        }
        let empty = SourceBatch {
            source_path: "retire.jsonl".into(),
            placements: Vec::new(),
            edges: Vec::new(),
            activities: Vec::new(),
            relation_complete: true,
            len_bytes: None,
            fingerprint: None,
            provider_id: None,
            resume_claim: None,
            entries: vec![],
        };
        store
            .commit_source_batches_if_changed(std::slice::from_ref(&empty))
            .unwrap();
        assert_eq!(store.count().unwrap(), 0);
        assert!(store.get(&ses).unwrap().is_none());
        assert!(store.get(&doc).unwrap().is_none());
    }

    #[test]
    fn shared_entity_survives_other_source_rescan() {
        // 两个源共享同一实体：一个源消失不退役另一源仍引用的实体。
        let store = SqliteStore::open_in_memory().unwrap();
        let shared = sid(IdKind::Document, b"shared-doc");
        let m1 = sid(IdKind::Message, b"share-m1");
        let m2 = sid(IdKind::Message, b"share-m2");
        let sources = [
            SourceBatch {
                source_path: "one.jsonl".into(),
                placements: Vec::new(),
                edges: Vec::new(),
                activities: Vec::new(),
                relation_complete: true,
                len_bytes: None,
                fingerprint: None,
                provider_id: None,
                resume_claim: None,
                entries: vec![
                    (m1.clone(), b"m1".to_vec(), "one text".into()),
                    (shared.clone(), b"d".to_vec(), String::new()),
                ],
            },
            SourceBatch {
                source_path: "two.jsonl".into(),
                placements: Vec::new(),
                edges: Vec::new(),
                activities: Vec::new(),
                relation_complete: true,
                len_bytes: None,
                fingerprint: None,
                provider_id: None,
                resume_claim: None,
                entries: vec![
                    (m2.clone(), b"m2".to_vec(), "two text".into()),
                    (shared.clone(), b"d".to_vec(), String::new()),
                ],
            },
        ];
        store.commit_source_batches_if_changed(&sources).unwrap();
        assert_eq!(store.count().unwrap(), 3);
        // 源 one 变空：m1 退役；shared 仍被 two 引用，保留。
        let shrunk = SourceBatch {
            source_path: "one.jsonl".into(),
            placements: Vec::new(),
            edges: Vec::new(),
            activities: Vec::new(),
            relation_complete: true,
            len_bytes: None,
            fingerprint: None,
            provider_id: None,
            resume_claim: None,
            entries: vec![],
        };
        store
            .commit_source_batches_if_changed(std::slice::from_ref(&shrunk))
            .unwrap();
        assert!(store.get(&m1).unwrap().is_none());
        assert!(store.get(&shared).unwrap().is_some());
        assert!(store.get(&m2).unwrap().is_some());
    }

    /// Canonical session payload for a source contributing `members`.
    fn session_payload(document: &str, members: &[&str]) -> Vec<u8> {
        serde_json::json!({
            "document": document,
            "documents": [document],
            "messages": members,
        })
        .to_string()
        .into_bytes()
    }

    fn session_members(store: &SqliteStore, id: &StableId) -> Vec<String> {
        let bytes = store.get(id).unwrap().expect("session must be present");
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        value["messages"]
            .as_array()
            .expect("messages array")
            .iter()
            .map(|entry| entry.as_str().expect("member is a string").to_string())
            .collect()
    }

    fn session_documents(store: &SqliteStore, id: &StableId) -> Vec<String> {
        let bytes = store.get(id).unwrap().expect("session must be present");
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        value["documents"]
            .as_array()
            .expect("documents array")
            .iter()
            .map(|entry| entry.as_str().expect("document is a string").to_string())
            .collect()
    }

    #[test]
    fn session_spanning_two_sources_in_one_batch_unions_its_members() {
        // 真实形态：一个逻辑会话被拆到多个 transcript 文件，每个源只声明自己那部分
        // 成员。旧行为把这判为冲突投影并拒绝整批（exit 6）；正确行为是取并集。
        let store = SqliteStore::open_in_memory().unwrap();
        let ses = sid(IdKind::Session, b"split-session");
        let doc_a = sid(IdKind::Document, b"split-doc-a");
        let doc_b = sid(IdKind::Document, b"split-doc-b");
        let m1 = sid(IdKind::Message, b"split-m1");
        let m2 = sid(IdKind::Message, b"split-m2");
        let sources = [
            SourceBatch {
                source_path: "part-a.jsonl".into(),
                placements: Vec::new(),
                edges: Vec::new(),
                activities: Vec::new(),
                relation_complete: true,
                len_bytes: None,
                fingerprint: None,
                provider_id: None,
                resume_claim: None,
                entries: vec![
                    (m1.clone(), b"m1".to_vec(), "first half".into()),
                    (
                        ses.clone(),
                        session_payload(doc_a.as_str(), &[m1.as_str()]),
                        String::new(),
                    ),
                    (doc_a.clone(), b"da".to_vec(), String::new()),
                ],
            },
            SourceBatch {
                source_path: "part-b.jsonl".into(),
                placements: Vec::new(),
                edges: Vec::new(),
                activities: Vec::new(),
                relation_complete: true,
                len_bytes: None,
                fingerprint: None,
                provider_id: None,
                resume_claim: None,
                entries: vec![
                    (m2.clone(), b"m2".to_vec(), "second half".into()),
                    (
                        ses.clone(),
                        session_payload(doc_b.as_str(), &[m2.as_str()]),
                        String::new(),
                    ),
                    (doc_b.clone(), b"db".to_vec(), String::new()),
                ],
            },
        ];
        assert!(store.commit_source_batches_if_changed(&sources).unwrap());
        assert_eq!(
            session_members(&store, &ses),
            vec![m1.as_str().to_string(), m2.as_str().to_string()],
        );
        // 两个贡献文档都保留；单值别名取升序首个，供旧读取方使用。
        let mut expected_docs = vec![doc_a.as_str().to_string(), doc_b.as_str().to_string()];
        expected_docs.sort();
        assert_eq!(session_documents(&store, &ses), expected_docs);
        let bytes = store.get(&ses).unwrap().unwrap();
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(value["document"], expected_docs[0].as_str());
    }

    #[test]
    fn session_synced_in_separate_batches_accumulates_members() {
        // 真实语料按批提交（命令行长度上限），所以合并必须以库中现值为起点：
        // 否则第二批的成员列表会覆盖第一批，只剩最后一批的成员。
        let store = SqliteStore::open_in_memory().unwrap();
        let ses = sid(IdKind::Session, b"batched-session");
        let doc_a = sid(IdKind::Document, b"batched-doc-a");
        let doc_b = sid(IdKind::Document, b"batched-doc-b");
        let m1 = sid(IdKind::Message, b"batched-m1");
        let m2 = sid(IdKind::Message, b"batched-m2");

        let first = SourceBatch {
            source_path: "batch-a.jsonl".into(),
            placements: Vec::new(),
            edges: Vec::new(),
            activities: Vec::new(),
            relation_complete: true,
            len_bytes: None,
            fingerprint: None,
            provider_id: None,
            resume_claim: None,
            entries: vec![
                (m1.clone(), b"m1".to_vec(), "batch a".into()),
                (
                    ses.clone(),
                    session_payload(doc_a.as_str(), &[m1.as_str()]),
                    String::new(),
                ),
                (doc_a.clone(), b"da".to_vec(), String::new()),
            ],
        };
        assert!(
            store
                .commit_source_batches_if_changed(std::slice::from_ref(&first))
                .unwrap()
        );

        let second = SourceBatch {
            source_path: "batch-b.jsonl".into(),
            placements: Vec::new(),
            edges: Vec::new(),
            activities: Vec::new(),
            relation_complete: true,
            len_bytes: None,
            fingerprint: None,
            provider_id: None,
            resume_claim: None,
            entries: vec![
                (m2.clone(), b"m2".to_vec(), "batch b".into()),
                (
                    ses.clone(),
                    session_payload(doc_b.as_str(), &[m2.as_str()]),
                    String::new(),
                ),
                (doc_b.clone(), b"db".to_vec(), String::new()),
            ],
        };
        assert!(
            store
                .commit_source_batches_if_changed(std::slice::from_ref(&second))
                .unwrap()
        );

        assert_eq!(
            session_members(&store, &ses),
            vec![m1.as_str().to_string(), m2.as_str().to_string()],
            "第二批不得覆盖第一批的成员",
        );
        assert_eq!(session_documents(&store, &ses).len(), 2);
    }

    #[test]
    fn resyncing_a_cross_source_session_is_a_content_level_noop() {
        // 合并结果必须稳定：同一语料重复 sync 不得推进 generation，否则每次运行都
        // 会作废所有分页 cursor。
        let store = SqliteStore::open_in_memory().unwrap();
        let ses = sid(IdKind::Session, b"noop-session");
        let doc_a = sid(IdKind::Document, b"noop-doc-a");
        let doc_b = sid(IdKind::Document, b"noop-doc-b");
        let m1 = sid(IdKind::Message, b"noop-m1");
        let m2 = sid(IdKind::Message, b"noop-m2");
        let sources = [
            SourceBatch {
                source_path: "noop-a.jsonl".into(),
                placements: Vec::new(),
                edges: Vec::new(),
                activities: Vec::new(),
                relation_complete: true,
                len_bytes: None,
                fingerprint: None,
                provider_id: None,
                resume_claim: None,
                entries: vec![
                    (m1.clone(), b"m1".to_vec(), "noop a".into()),
                    (
                        ses.clone(),
                        session_payload(doc_a.as_str(), &[m1.as_str()]),
                        String::new(),
                    ),
                    (doc_a.clone(), b"da".to_vec(), String::new()),
                ],
            },
            SourceBatch {
                source_path: "noop-b.jsonl".into(),
                placements: Vec::new(),
                edges: Vec::new(),
                activities: Vec::new(),
                relation_complete: true,
                len_bytes: None,
                fingerprint: None,
                provider_id: None,
                resume_claim: None,
                entries: vec![
                    (m2.clone(), b"m2".to_vec(), "noop b".into()),
                    (
                        ses.clone(),
                        session_payload(doc_b.as_str(), &[m2.as_str()]),
                        String::new(),
                    ),
                    (doc_b.clone(), b"db".to_vec(), String::new()),
                ],
            },
        ];
        assert!(store.commit_source_batches_if_changed(&sources).unwrap());
        let generation = store.active_generation().unwrap();
        assert!(
            !store.commit_source_batches_if_changed(&sources).unwrap(),
            "重复提交同一跨源语料应为内容级 no-op",
        );
        assert_eq!(store.active_generation().unwrap(), generation);
    }

    #[test]
    fn legacy_single_document_session_upgrades_without_losing_members() {
        // 升级前入库的会话行只有单值 `document`，且没有 `documents` 数组。
        // 新二进制再次 sync 时必须把旧成员并进来，而不是丢弃或报错。
        let store = SqliteStore::open_in_memory().unwrap();
        let ses = sid(IdKind::Session, b"legacy-session");
        let doc_a = sid(IdKind::Document, b"legacy-doc-a");
        let doc_b = sid(IdKind::Document, b"legacy-doc-b");
        let m1 = sid(IdKind::Message, b"legacy-m1");
        let m2 = sid(IdKind::Message, b"legacy-m2");

        let legacy_payload = serde_json::json!({
            "document": doc_a.as_str(),
            "messages": [m1.as_str()],
        })
        .to_string()
        .into_bytes();
        let legacy = SourceBatch {
            source_path: "legacy-a.jsonl".into(),
            placements: Vec::new(),
            edges: Vec::new(),
            activities: Vec::new(),
            relation_complete: true,
            len_bytes: None,
            fingerprint: None,
            provider_id: None,
            resume_claim: None,
            entries: vec![
                (m1.clone(), b"m1".to_vec(), "legacy a".into()),
                (ses.clone(), legacy_payload, String::new()),
                (doc_a.clone(), b"da".to_vec(), String::new()),
            ],
        };
        assert!(
            store
                .commit_source_batches_if_changed(std::slice::from_ref(&legacy))
                .unwrap()
        );

        let modern = SourceBatch {
            source_path: "legacy-b.jsonl".into(),
            placements: Vec::new(),
            edges: Vec::new(),
            activities: Vec::new(),
            relation_complete: true,
            len_bytes: None,
            fingerprint: None,
            provider_id: None,
            resume_claim: None,
            entries: vec![
                (m2.clone(), b"m2".to_vec(), "legacy b".into()),
                (
                    ses.clone(),
                    session_payload(doc_b.as_str(), &[m2.as_str()]),
                    String::new(),
                ),
                (doc_b.clone(), b"db".to_vec(), String::new()),
            ],
        };
        assert!(
            store
                .commit_source_batches_if_changed(std::slice::from_ref(&modern))
                .unwrap()
        );

        assert_eq!(
            session_members(&store, &ses),
            vec![m1.as_str().to_string(), m2.as_str().to_string()],
        );
        assert_eq!(session_documents(&store, &ses).len(), 2);
    }

    #[test]
    fn conflicting_message_projections_are_still_rejected() {
        // 合并只对容器实体开放。同一条消息在不同源上投影不同是真实的不一致
        // （同一 native id 却内容不同），必须继续拒绝，不能被容器合并顺带放行。
        let store = SqliteStore::open_in_memory().unwrap();
        let native_id = "private-provider-native-id";
        let msg = StableId::native(IdKind::Message, native_id);
        let sources = [
            SourceBatch {
                source_path: "conflict-a.jsonl".into(),
                placements: Vec::new(),
                edges: Vec::new(),
                activities: Vec::new(),
                relation_complete: true,
                len_bytes: None,
                fingerprint: None,
                provider_id: None,
                resume_claim: None,
                entries: vec![(msg.clone(), b"first projection".to_vec(), "one".into())],
            },
            SourceBatch {
                source_path: "conflict-b.jsonl".into(),
                placements: Vec::new(),
                edges: Vec::new(),
                activities: Vec::new(),
                relation_complete: true,
                len_bytes: None,
                fingerprint: None,
                provider_id: None,
                resume_claim: None,
                entries: vec![(msg.clone(), b"second projection".to_vec(), "two".into())],
            },
        ];
        let error = store
            .commit_source_batches_if_changed(&sources)
            .expect_err("conflicting message projections must be rejected");
        assert!(
            format!("{error}").contains("conflicting projections"),
            "{error}"
        );
        assert!(!format!("{error}").contains(native_id), "{error}");
        assert!(!format!("{error}").contains(msg.as_str()), "{error}");
    }

    /// Build the canonical message payload shape that ingest writes.
    fn message_payload(session: &str, text: &str) -> Vec<u8> {
        serde_json::json!({
            "role": "user",
            "text": text,
            "parent": null,
            "session": session,
            "span": { "start": 0, "end": 10 },
        })
        .to_string()
        .into_bytes()
    }

    /// Same message as it appears in one specific file: the copy sits at that
    /// file's own byte offsets and names the document it came from.
    fn message_payload_with_span(
        session: &str,
        text: &str,
        document: &str,
        start: u64,
        end: u64,
    ) -> Vec<u8> {
        serde_json::json!({
            "role": "user",
            "text": text,
            "parent": null,
            "session": session,
            "sessions": [session],
            "span": { "start": start, "end": end },
            "spans": [{ "document": document, "start": start, "end": end }],
        })
        .to_string()
        .into_bytes()
    }

    #[test]
    fn codex_timestamp_occurrence_projections_merge_without_conflict() {
        // Codex's old adapter stored the occurrence-local envelope timestamp
        // as the message timestamp; the current adapter emits no stable
        // timestamp. Re-ingesting an old catalog must therefore merge a
        // string timestamp with null instead of reporting a conflict.
        let store = SqliteStore::open_in_memory().unwrap();
        let msg = StableId::native(IdKind::Message, "codex-msg-timestamp");
        let old = serde_json::json!({
            "role": "assistant",
            "text": "same body",
            "timestamp": "2026-07-19T23:40:01.000Z",
        })
        .to_string()
        .into_bytes();
        let new = serde_json::json!({
            "role": "assistant",
            "text": "same body",
            "timestamp": null,
        })
        .to_string()
        .into_bytes();
        let sources = [
            SourceBatch {
                source_path: "old-codex.jsonl".into(),
                placements: Vec::new(),
                edges: Vec::new(),
                activities: Vec::new(),
                relation_complete: true,
                len_bytes: None,
                fingerprint: None,
                provider_id: None,
                resume_claim: None,
                entries: vec![(msg.clone(), old, "one".into())],
            },
            SourceBatch {
                source_path: "new-codex.jsonl".into(),
                placements: Vec::new(),
                edges: Vec::new(),
                activities: Vec::new(),
                relation_complete: true,
                len_bytes: None,
                fingerprint: None,
                provider_id: None,
                resume_claim: None,
                entries: vec![(msg.clone(), new, "two".into())],
            },
        ];
        store
            .commit_source_batches_if_changed(&sources)
            .expect("occurrence timestamp string/null projections must merge");
        let stored = store.get(&msg).unwrap().unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&stored).unwrap();
        assert_eq!(
            payload.get("timestamp"),
            Some(&serde_json::Value::Null),
            "merged message must carry no stable timestamp"
        );
        assert_eq!(payload.get("text"), Some(&serde_json::json!("same body")));
    }

    #[test]
    fn codex_timestamp_merge_converges_to_null_regardless_of_side() {
        // The string/null convergence must not depend on which projection is
        // the left (merge) side.
        let store = SqliteStore::open_in_memory().unwrap();
        let msg = StableId::native(IdKind::Message, "codex-msg-timestamp-side");
        let string_payload = serde_json::json!({
            "role": "assistant",
            "text": "same body",
            "timestamp": "2026-07-19T23:40:01.000Z",
        })
        .to_string()
        .into_bytes();
        let null_payload = serde_json::json!({
            "role": "assistant",
            "text": "same body",
            "timestamp": null,
        })
        .to_string()
        .into_bytes();
        let sources = [
            SourceBatch {
                source_path: "null-first.jsonl".into(),
                placements: Vec::new(),
                edges: Vec::new(),
                activities: Vec::new(),
                relation_complete: true,
                len_bytes: None,
                fingerprint: None,
                provider_id: None,
                resume_claim: None,
                entries: vec![(msg.clone(), null_payload, "one".into())],
            },
            SourceBatch {
                source_path: "string-second.jsonl".into(),
                placements: Vec::new(),
                edges: Vec::new(),
                activities: Vec::new(),
                relation_complete: true,
                len_bytes: None,
                fingerprint: None,
                provider_id: None,
                resume_claim: None,
                entries: vec![(msg.clone(), string_payload, "two".into())],
            },
        ];
        store
            .commit_source_batches_if_changed(&sources)
            .expect("null-first/string-second must merge");
        let stored = store.get(&msg).unwrap().unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&stored).unwrap();
        assert_eq!(
            payload.get("timestamp"),
            Some(&serde_json::Value::Null),
            "timestamp must converge to null in either order"
        );
    }

    #[test]
    fn message_copied_into_another_file_unions_its_per_document_spans() {
        // A resumed conversation's history is rewritten into the new transcript,
        // so the same message sits at a different byte offset in each file. Those
        // offsets are per-source facts: keep both, keyed by document, instead of
        // calling the difference a conflict.
        let store = SqliteStore::open_in_memory().unwrap();
        let msg = sid(IdKind::Message, b"respanned-msg");
        let sources = [
            SourceBatch {
                source_path: "original.jsonl".into(),
                placements: Vec::new(),
                edges: Vec::new(),
                activities: Vec::new(),
                relation_complete: true,
                len_bytes: None,
                fingerprint: None,
                provider_id: None,
                resume_claim: None,
                entries: vec![(
                    msg.clone(),
                    message_payload_with_span("ses_v1_aaa", "same body", "doc_v1_aaa", 0, 929),
                    "same body".into(),
                )],
            },
            SourceBatch {
                source_path: "resumed.jsonl".into(),
                placements: Vec::new(),
                edges: Vec::new(),
                activities: Vec::new(),
                relation_complete: true,
                len_bytes: None,
                fingerprint: None,
                provider_id: None,
                resume_claim: None,
                entries: vec![(
                    msg.clone(),
                    message_payload_with_span("ses_v1_bbb", "same body", "doc_v1_bbb", 512, 1322),
                    "same body".into(),
                )],
            },
        ];
        assert!(store.commit_source_batches_if_changed(&sources).unwrap());

        let stored: serde_json::Value =
            serde_json::from_slice(&store.get(&msg).unwrap().unwrap()).unwrap();
        let spans = stored["spans"].as_array().expect("spans array");
        assert_eq!(spans.len(), 2, "both locations must survive: {stored}");
        // Keyed by document and ordered by it, so the result does not depend on
        // which file happened to be scanned first.
        assert_eq!(spans[0]["document"], "doc_v1_aaa");
        assert_eq!(spans[0]["end"], 929);
        assert_eq!(spans[1]["document"], "doc_v1_bbb");
        assert_eq!(spans[1]["start"], 512);
        // The singular alias still names one real location, so evidence
        // assembly keeps reporting byte precision rather than degrading.
        assert_eq!(stored["span"]["start"], 0);
        assert_eq!(stored["span"]["end"], 929);

        // Re-syncing the same corpus changes nothing: spans are keyed by
        // document, so a second pass maps onto the same two entries.
        assert!(!store.commit_source_batches_if_changed(&sources).unwrap());
    }

    #[test]
    fn message_shared_by_resumed_sessions_unions_its_session_refs() {
        // Resuming or forking a session copies history into the new transcript,
        // so one message id legitimately appears under several session ids with
        // otherwise identical content. That must union, not conflict.
        let store = SqliteStore::open_in_memory().unwrap();
        let msg = sid(IdKind::Message, b"resumed-msg");
        let sources = [
            SourceBatch {
                source_path: "first.jsonl".into(),
                placements: Vec::new(),
                edges: Vec::new(),
                activities: Vec::new(),
                relation_complete: true,
                len_bytes: None,
                fingerprint: None,
                provider_id: None,
                resume_claim: None,
                entries: vec![(
                    msg.clone(),
                    message_payload("ses_v1_aaa", "shared body"),
                    "shared body".into(),
                )],
            },
            SourceBatch {
                source_path: "second.jsonl".into(),
                placements: Vec::new(),
                edges: Vec::new(),
                activities: Vec::new(),
                relation_complete: true,
                len_bytes: None,
                fingerprint: None,
                provider_id: None,
                resume_claim: None,
                entries: vec![(
                    msg.clone(),
                    message_payload("ses_v1_bbb", "shared body"),
                    "shared body".into(),
                )],
            },
        ];
        assert!(store.commit_source_batches_if_changed(&sources).unwrap());

        let stored: serde_json::Value =
            serde_json::from_slice(&store.get(&msg).unwrap().unwrap()).unwrap();
        assert_eq!(
            stored["sessions"],
            serde_json::json!(["ses_v1_aaa", "ses_v1_bbb"]),
            "both owning sessions must be recorded: {stored}"
        );
        // The single-value alias keeps pre-union readers working.
        assert_eq!(stored["session"], "ses_v1_aaa");
        // Everything else is untouched by the merge.
        assert_eq!(stored["text"], "shared body");
        assert_eq!(stored["span"]["end"], 10);
    }

    #[test]
    fn message_with_different_text_merges_to_longer_projection() {
        // text is a content projection, not a stable identity field: Claude
        // Code copies a conversation's history into a new transcript on resume
        // or fork, and a copy may carry a different number of content blocks
        // (e.g. a truncated tool_result). Diverging text under one id must not
        // conflict; the merged projection deterministically keeps the longer
        // body so no retrieved content is lost.
        let store = SqliteStore::open_in_memory().unwrap();
        let msg = sid(IdKind::Message, b"divergent-msg");
        let sources = [
            SourceBatch {
                source_path: "first.jsonl".into(),
                placements: Vec::new(),
                edges: Vec::new(),
                activities: Vec::new(),
                relation_complete: true,
                len_bytes: None,
                fingerprint: None,
                provider_id: None,
                resume_claim: None,
                entries: vec![(
                    msg.clone(),
                    message_payload("ses_v1_aaa", "original body"),
                    "original body".into(),
                )],
            },
            SourceBatch {
                source_path: "second.jsonl".into(),
                placements: Vec::new(),
                edges: Vec::new(),
                activities: Vec::new(),
                relation_complete: true,
                len_bytes: None,
                fingerprint: None,
                provider_id: None,
                resume_claim: None,
                entries: vec![(
                    msg.clone(),
                    message_payload("ses_v1_aaa", "a much longer rewritten body"),
                    "a much longer rewritten body".into(),
                )],
            },
        ];
        store
            .commit_source_batches_if_changed(&sources)
            .expect("diverging text is exempt from conflict and must merge");
        // The longer projection wins deterministically.
        let stored = store
            .get(&msg)
            .expect("message must be stored")
            .expect("message must be present");
        let stored_payload: serde_json::Value =
            serde_json::from_slice::<serde_json::Value>(&stored)
                .expect("stored payload must parse");
        assert_eq!(
            stored_payload["text"], "a much longer rewritten body",
            "merged text must keep the longer projection"
        );
    }

    #[test]
    fn merged_message_fts_projects_from_merged_payload() {
        // 回归（Major-1）：合并 payload 后，FTS 正文必须从合并后 payload 经
        // searchable_text 重投影（与 rebuild_index 同一投影函数），而不是取
        // “source_path 排序最后处理的源”的原始 text。长文本在排序靠前的源、
        // 短文本在排序靠后的源时，旧实现把长文本写进 catalog payload 却把短
        // 文本写进 fts——长文本搜不到（需 rebuild 才恢复），且按源分批重同步
        // 会交替改写 fts、每批推进 generation、内容级 no-op 失效。
        let store = SqliteStore::open_in_memory().unwrap();
        let msg = sid(IdKind::Message, b"merged-fts-msg");
        let sources = [
            SourceBatch {
                source_path: "aaa-long.jsonl".into(),
                placements: Vec::new(),
                edges: Vec::new(),
                activities: Vec::new(),
                relation_complete: true,
                len_bytes: None,
                fingerprint: None,
                provider_id: None,
                resume_claim: None,
                entries: vec![(
                    msg.clone(),
                    message_payload("ses_v1_aaa", "the long body that must stay searchable"),
                    "the long body that must stay searchable".into(),
                )],
            },
            SourceBatch {
                source_path: "zzz-short.jsonl".into(),
                placements: Vec::new(),
                edges: Vec::new(),
                activities: Vec::new(),
                relation_complete: true,
                len_bytes: None,
                fingerprint: None,
                provider_id: None,
                resume_claim: None,
                entries: vec![(
                    msg.clone(),
                    message_payload("ses_v1_aaa", "short body"),
                    "short body".into(),
                )],
            },
        ];
        assert!(store.commit_source_batches_if_changed(&sources).unwrap());
        // 长文本必须可搜——它是合并 payload 的权威投影。
        assert_eq!(
            store.query("long body", 10).unwrap().len(),
            1,
            "merged payload text must be searchable"
        );
        assert!(
            store.query("short", 10).unwrap().is_empty(),
            "short projection must not shadow the merged text"
        );
        // fts 行文本 == searchable_text(合并后 payload)。
        let conn = store.conn.borrow();
        let fts_text: String = conn
            .query_row(
                "SELECT f.text FROM fts f
                 JOIN fts_ids fi ON fi.id_json = f.id
                 WHERE fi.wire_id = ?1",
                [msg.as_str()],
                |row| row.get(0),
            )
            .unwrap();
        drop(conn);
        assert_eq!(
            fts_text, "the long body that must stay searchable",
            "fts must project from the merged payload"
        );
        // 内容级 no-op 恢复：同一语料重同步不推进 generation。
        let generation = store.active_generation().unwrap();
        assert!(!store.commit_source_batches_if_changed(&sources).unwrap());
        assert_eq!(store.active_generation().unwrap(), generation);
    }

    #[test]
    fn message_payload_only_change_is_not_dropped() {
        // 回归（Minor-2）：contextual payload 判定必须比对字节（经与提交路径相同
        // 的合并），而不是只查 catalog 行存在。text 不变、仅 payload 变化（新增
        // session 引用）时，旧实现把 batch 判为 current，payload-only 变更被静默
        // 丢弃，搜索与上下文永远缺该 session。
        let store = SqliteStore::open_in_memory().unwrap();
        let msg = sid(IdKind::Message, b"payload-only-msg");
        let first = SourceBatch {
            source_path: "payload-only.jsonl".into(),
            placements: Vec::new(),
            edges: Vec::new(),
            activities: Vec::new(),
            relation_complete: true,
            len_bytes: None,
            fingerprint: None,
            provider_id: None,
            resume_claim: None,
            entries: vec![(
                msg.clone(),
                message_payload("ses_v1_aaa", "stable body"),
                "stable body".into(),
            )],
        };
        assert!(
            store
                .commit_source_batches_if_changed(std::slice::from_ref(&first))
                .unwrap()
        );

        // text 不变、payload 换 session（同一源路径，membership/relations 均不变）。
        let changed = SourceBatch {
            source_path: "payload-only.jsonl".into(),
            placements: Vec::new(),
            edges: Vec::new(),
            activities: Vec::new(),
            relation_complete: true,
            len_bytes: None,
            fingerprint: None,
            provider_id: None,
            resume_claim: None,
            entries: vec![(
                msg.clone(),
                message_payload("ses_v1_bbb", "stable body"),
                "stable body".into(),
            )],
        };
        assert!(
            store
                .commit_source_batches_if_changed(std::slice::from_ref(&changed))
                .unwrap(),
            "payload-only change must not be silently dropped"
        );
        let stored: serde_json::Value =
            serde_json::from_slice(&store.get(&msg).unwrap().unwrap()).unwrap();
        assert_eq!(
            stored["sessions"],
            serde_json::json!(["ses_v1_aaa", "ses_v1_bbb"]),
            "merged payload must accumulate the new session ref"
        );
        // 已收敛：内容与存储一致后重同步是 no-op。
        assert!(
            !store
                .commit_source_batches_if_changed(std::slice::from_ref(&changed))
                .unwrap()
        );
    }

    #[test]
    fn changed_source_fingerprint_forces_reparse_and_converges() {
        // 回归（Minor-3）：source_scans 的 len/fingerprint 指纹参与 current 判定
        // （cheap 与 B2 no-op 两条路径都查）。内容等长替换后，缓存指纹不匹配的源
        // 必须重解析并重写缓存；只查扫描行存在会让指纹缓存永不收敛，CLI 每次运行
        // 都重解析全部源。
        let store = SqliteStore::open_in_memory().unwrap();
        let a = sid(IdKind::Message, b"fingerprint-msg");
        let source = |fingerprint: &str| SourceBatch {
            source_path: "fingerprint.jsonl".into(),
            placements: Vec::new(),
            edges: Vec::new(),
            activities: Vec::new(),
            relation_complete: true,
            len_bytes: Some(10),
            fingerprint: Some(fingerprint.to_string()),
            provider_id: None,
            resume_claim: None,
            entries: vec![(a.clone(), b"payload".to_vec(), "same text".into())],
        };
        assert!(
            store
                .commit_source_batches_if_changed(std::slice::from_ref(&source("aaa")))
                .unwrap()
        );
        // 等长异容替换：len 相同、fingerprint 不同 → 不得判为 current。
        assert!(
            store
                .commit_source_batches_if_changed(std::slice::from_ref(&source("bbb")))
                .unwrap(),
            "fingerprint change must force a re-scan commit"
        );
        // 指纹已重写为 bbb → 再次重同步是 no-op，缓存收敛。
        assert!(
            !store
                .commit_source_batches_if_changed(std::slice::from_ref(&source("bbb")))
                .unwrap()
        );
        let fingerprints = store
            .source_fingerprints(&["fingerprint.jsonl".to_string()])
            .unwrap();
        assert_eq!(
            fingerprints.get("fingerprint.jsonl"),
            Some(&(Some(10), Some("bbb".to_string())))
        );
    }

    #[test]
    fn open_for_write_accepts_bare_relative_filename() {
        // 回归（Minor-4）：裸相对文件名（"catalog.db"）的 parent() 是空串 "",
        // create_dir_all("") 会报错；空 parent 应按当前工作目录处理。
        let dir = tempfile::tempdir().unwrap();
        let original = std::env::current_dir().unwrap();
        std::env::set_current_dir(dir.path()).unwrap();
        let result = SqliteStore::open_for_write("catalog.db");
        std::env::set_current_dir(original).unwrap();
        let store = result.unwrap();
        assert_eq!(store.count().unwrap(), 0);
        assert!(
            dir.path().join("writer.lock").exists(),
            "writer lease must be created next to the bare filename"
        );
        assert!(dir.path().join("catalog.db").exists());
    }

    #[test]
    fn standalone_index_keeps_non_message_out_of_fts() {
        // 回归（Minor-5）：单条 SearchIndex::index 与批量路径一样只让 Message
        // 实体进入 fts 全文表——session/document 是容器实体，索引其正文会让搜索
        // 命中重复计数。
        let store = SqliteStore::open_in_memory().unwrap();
        let ses = sid(IdKind::Session, b"index-container");
        store.index(&ses, "container body").unwrap();
        assert!(
            store.query("container", 10).unwrap().is_empty(),
            "non-message entities must not enter the fts table"
        );
        let conn = store.conn.borrow();
        let fts_rowid: Option<i64> = conn
            .query_row(
                "SELECT fts_rowid FROM fts_ids WHERE wire_id = ?1",
                [ses.as_str()],
                |row| row.get(0),
            )
            .unwrap();
        drop(conn);
        assert_eq!(fts_rowid, None, "non-message sidecar row stays NULL");
        // Message 走同一路径仍正常进 fts。
        let msg = sid(IdKind::Message, b"index-message");
        store.index(&msg, "searchable body").unwrap();
        assert_eq!(store.query("searchable", 10).unwrap().len(), 1);
    }

    #[test]
    fn fresh_schema_carries_fts_rowid_without_open_time_ddl() {
        // 回归（Minor-6）：fts_rowid 列直接进 v3 建表 DDL，新库首次 open（含只读）
        // 不再执行 ALTER+回填事务；旧 v7 库仍走 ensure_fts_ids_rowid 的一次性回填。
        let store = SqliteStore::open_in_memory().unwrap();
        let conn = store.conn.borrow();
        let has_fts_rowid: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM pragma_table_info('fts_ids') WHERE name = 'fts_rowid'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        drop(conn);
        assert_eq!(has_fts_rowid, 1);
    }

    #[test]
    fn batch_current_check_is_rowid_scoped_not_content_scanned() {
        // 回归（性能护栏，Minor-8）：batch_is_current 逐条读 fts text 时，旧实现
        // 按内容列 id 比较整表扫描（每条 O(全库)，B1 批量 no-op 判定 O(N²)）；改经
        // fts_ids.fts_rowid 按 rowid 定位后 O(N)。10K 库上内容扫描路径远超 3s 宽限
        // （单次整表扫描约 6.3s），rowid 路径有数量级余量。
        let store = SqliteStore::open_in_memory().unwrap();
        let entries: Vec<(StableId, Vec<u8>, String)> = (0..10_000)
            .map(|i| {
                let id = sid(IdKind::Message, format!("current-{i}").as_bytes());
                (
                    id,
                    format!("payload {i}").into_bytes(),
                    format!("current text {i}"),
                )
            })
            .collect();
        assert!(store.commit_batch_if_changed(&entries).unwrap());
        let started = std::time::Instant::now();
        assert!(!store.commit_batch_if_changed(&entries).unwrap());
        let elapsed = started.elapsed();
        assert!(
            elapsed < std::time::Duration::from_secs(3),
            "current check must not scan the fts table per message: {elapsed:?}"
        );
    }

    #[test]
    fn b1_delete_rejects_catalog_entity_still_referenced_by_relations() {
        // 回归（Minor-10）：B1 路径（裸 commit_index_batch）删 catalog 实体而 v7
        // 关系行仍引用它时，必须拒绝整批，而不是留下事后才发现的悬空引用。
        let store = SqliteStore::open_in_memory().unwrap();
        let session = sid(IdKind::Session, b"dangling-session");
        let document = sid(IdKind::Document, b"dangling-document");
        let message = sid(IdKind::Message, b"dangling-message");
        let p = placement(&session, &document, &message, 0, false, Some((1, 5)));
        let source = source_batch(
            "dangling.jsonl",
            vec![
                (message.clone(), b"m".to_vec(), "dangling text".into()),
                (session.clone(), b"s".to_vec(), String::new()),
                (document.clone(), b"d".to_vec(), String::new()),
            ],
            vec![p],
            Vec::new(),
            true,
        );
        assert!(
            store
                .commit_source_batches_if_changed(std::slice::from_ref(&source))
                .unwrap()
        );

        // 裸 B1 删除被 placement 引用的 message 实体 → 拒绝。
        let pending = store
            .begin_index_batch(&[], std::slice::from_ref(&message))
            .unwrap();
        let error = store
            .commit_index_batch(&pending, &[], &[message])
            .expect_err("deleting a referenced catalog entity must fail");
        assert!(format!("{error}").contains("still referenced"), "{error}");
        // 事务回滚：实体仍在，generation 未推进。
        assert!(
            store
                .get(&sid(IdKind::Message, b"dangling-message"))
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn put_maintains_fts_projection() {
        // 回归（Minor-11）：put 更新 payload 后必须同步维护 fts/边车——旧文本不可
        // 再搜、新 payload 的 text 可搜（与 rebuild 同一 searchable_text 投影），
        // 且按 wire 删除仍能经边车定位新 fts 行。
        let store = SqliteStore::open_in_memory().unwrap();
        let msg = sid(IdKind::Message, b"put-fts-msg");
        let source = SourceBatch {
            source_path: "put.jsonl".into(),
            placements: Vec::new(),
            edges: Vec::new(),
            activities: Vec::new(),
            relation_complete: true,
            len_bytes: None,
            fingerprint: None,
            provider_id: None,
            resume_claim: None,
            entries: vec![(
                msg.clone(),
                message_payload("ses_v1_aaa", "old body"),
                "old body".into(),
            )],
        };
        assert!(
            store
                .commit_source_batches_if_changed(std::slice::from_ref(&source))
                .unwrap()
        );
        assert_eq!(store.query("old", 10).unwrap().len(), 1);
        store
            .put(&msg, &message_payload("ses_v1_aaa", "brand new body"))
            .unwrap();
        assert!(
            store.query("old", 10).unwrap().is_empty(),
            "put must retire the old indexed text"
        );
        assert_eq!(store.query("brand", 10).unwrap().len(), 1);
        let entries: [(StableId, Vec<u8>, String); 0] = [];
        let pending = store
            .begin_index_batch(&entries, std::slice::from_ref(&msg))
            .unwrap();
        store
            .commit_index_batch(&pending, &entries, std::slice::from_ref(&msg))
            .unwrap();
        assert!(store.query("brand", 10).unwrap().is_empty());
    }

    #[test]
    fn timestamp_missing_key_is_symmetric_with_explicit_null() {
        // 回归（Minor-7）：timestamp 缺失键与显式 null 对称收敛——一侧带字符串
        // 时间戳、另一侧缺失该键时，合并结果必须收敛为 null（与 string/null 相同），
        // 而不是保留字符串；两侧都缺失时不引入 timestamp 键。
        let string_payload = serde_json::json!({
            "role": "assistant",
            "text": "same body",
            "timestamp": "2026-07-19T23:40:01.000Z",
        })
        .to_string()
        .into_bytes();
        let missing_payload = serde_json::json!({
            "role": "assistant",
            "text": "same body",
        })
        .to_string()
        .into_bytes();
        let merged = merge_message_payloads("wire", &string_payload, &missing_payload).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&merged).unwrap();
        assert_eq!(value.get("timestamp"), Some(&serde_json::Value::Null));
        // 方向对称。
        let merged = merge_message_payloads("wire", &missing_payload, &string_payload).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&merged).unwrap();
        assert_eq!(value.get("timestamp"), Some(&serde_json::Value::Null));
        // 两侧都缺失：不引入 timestamp 键。
        let merged = merge_message_payloads("wire", &missing_payload, &missing_payload).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&merged).unwrap();
        assert!(value.get("timestamp").is_none());
    }

    #[test]
    fn message_session_refs_accumulate_across_separate_batches() {
        // The same message arriving in a later batch must add its session
        // without dropping the ones already recorded.
        let store = SqliteStore::open_in_memory().unwrap();
        let msg = sid(IdKind::Message, b"batched-msg");
        let first = SourceBatch {
            source_path: "first.jsonl".into(),
            placements: Vec::new(),
            edges: Vec::new(),
            activities: Vec::new(),
            relation_complete: true,
            len_bytes: None,
            fingerprint: None,
            provider_id: None,
            resume_claim: None,
            entries: vec![(
                msg.clone(),
                message_payload("ses_v1_aaa", "body"),
                "body".into(),
            )],
        };
        assert!(
            store
                .commit_source_batches_if_changed(std::slice::from_ref(&first))
                .unwrap()
        );
        let second = SourceBatch {
            source_path: "second.jsonl".into(),
            placements: Vec::new(),
            edges: Vec::new(),
            activities: Vec::new(),
            relation_complete: true,
            len_bytes: None,
            fingerprint: None,
            provider_id: None,
            resume_claim: None,
            entries: vec![(
                msg.clone(),
                message_payload("ses_v1_bbb", "body"),
                "body".into(),
            )],
        };
        assert!(
            store
                .commit_source_batches_if_changed(std::slice::from_ref(&second))
                .unwrap()
        );

        let stored: serde_json::Value =
            serde_json::from_slice(&store.get(&msg).unwrap().unwrap()).unwrap();
        assert_eq!(
            stored["sessions"],
            serde_json::json!(["ses_v1_aaa", "ses_v1_bbb"]),
            "earlier batch's session must survive: {stored}"
        );
    }

    #[test]
    fn shared_message_survives_one_source_shrinking() {
        let store = SqliteStore::open_in_memory().unwrap();
        let shared = sid(IdKind::Message, b"shared");
        let first = [
            SourceBatch {
                source_path: "one".into(),
                placements: Vec::new(),
                edges: Vec::new(),
                activities: Vec::new(),
                relation_complete: true,
                len_bytes: None,
                fingerprint: None,
                provider_id: None,
                resume_claim: None,
                entries: vec![(shared.clone(), b"p".to_vec(), "shared text".into())],
            },
            SourceBatch {
                source_path: "two".into(),
                placements: Vec::new(),
                edges: Vec::new(),
                activities: Vec::new(),
                relation_complete: true,
                len_bytes: None,
                fingerprint: None,
                provider_id: None,
                resume_claim: None,
                entries: vec![(shared.clone(), b"p".to_vec(), "shared text".into())],
            },
        ];
        assert!(store.commit_source_batches_if_changed(&first).unwrap());
        let second = [
            SourceBatch {
                source_path: "one".into(),
                placements: Vec::new(),
                edges: Vec::new(),
                activities: Vec::new(),
                relation_complete: true,
                len_bytes: None,
                fingerprint: None,
                provider_id: None,
                resume_claim: None,
                entries: Vec::new(),
            },
            SourceBatch {
                source_path: "two".into(),
                placements: Vec::new(),
                edges: Vec::new(),
                activities: Vec::new(),
                relation_complete: true,
                len_bytes: None,
                fingerprint: None,
                provider_id: None,
                resume_claim: None,
                entries: vec![(shared.clone(), b"p".to_vec(), "shared text".into())],
            },
        ];
        assert!(store.commit_source_batches_if_changed(&second).unwrap());
        assert_eq!(store.count().unwrap(), 1);
        assert!(store.get(&shared).unwrap().is_some());
        assert_eq!(store.query("shared", 10).unwrap().len(), 1);
    }

    #[test]
    fn moving_message_to_new_source_is_atomic() {
        let store = SqliteStore::open_in_memory().unwrap();
        let moved = sid(IdKind::Message, b"move-to-new-source");
        let original = SourceBatch {
            source_path: "source-a".into(),
            placements: Vec::new(),
            edges: Vec::new(),
            activities: Vec::new(),
            relation_complete: true,
            len_bytes: None,
            fingerprint: None,
            provider_id: None,
            resume_claim: None,
            entries: vec![(moved.clone(), b"p".to_vec(), "moved text".into())],
        };
        store
            .commit_source_batches_if_changed(std::slice::from_ref(&original))
            .unwrap();

        let moved_batches = [
            SourceBatch {
                source_path: "source-a".into(),
                placements: Vec::new(),
                edges: Vec::new(),
                activities: Vec::new(),
                relation_complete: true,
                len_bytes: None,
                fingerprint: None,
                provider_id: None,
                resume_claim: None,
                entries: Vec::new(),
            },
            SourceBatch {
                source_path: "source-b".into(),
                placements: Vec::new(),
                edges: Vec::new(),
                activities: Vec::new(),
                relation_complete: true,
                len_bytes: None,
                fingerprint: None,
                provider_id: None,
                resume_claim: None,
                entries: vec![(moved.clone(), b"p".to_vec(), "moved text".into())],
            },
        ];
        assert!(
            store
                .commit_source_batches_if_changed(&moved_batches)
                .unwrap()
        );
        assert_eq!(store.active_generation().unwrap(), 2);
        assert_eq!(store.get(&moved).unwrap().unwrap(), b"p");
        assert_eq!(store.query("moved", 10).unwrap().len(), 1);
        assert_eq!(
            store.source_message_ids("source-a").unwrap(),
            Vec::<String>::new()
        );
        assert_eq!(
            store.source_message_ids("source-b").unwrap(),
            vec![moved.as_str().to_string()]
        );
    }

    #[test]
    fn source_batch_permutations_produce_identical_state() {
        fn run(order: [usize; 3]) -> SourceState {
            let store = SqliteStore::open_in_memory().unwrap();
            let moved = sid(IdKind::Message, b"permuted-move");
            let removed = sid(IdKind::Message, b"permuted-remove");
            let kept = sid(IdKind::Message, b"permuted-keep");
            let initial = [
                SourceBatch {
                    source_path: "source-a".into(),
                    placements: Vec::new(),
                    edges: Vec::new(),
                    activities: Vec::new(),
                    relation_complete: true,
                    len_bytes: None,
                    fingerprint: None,
                    provider_id: None,
                    resume_claim: None,
                    entries: vec![
                        (moved.clone(), b"m".to_vec(), "moved text".into()),
                        (removed.clone(), b"r".to_vec(), "removed text".into()),
                    ],
                },
                SourceBatch {
                    source_path: "source-c".into(),
                    placements: Vec::new(),
                    edges: Vec::new(),
                    activities: Vec::new(),
                    relation_complete: true,
                    len_bytes: None,
                    fingerprint: None,
                    provider_id: None,
                    resume_claim: None,
                    entries: vec![(kept.clone(), b"k".to_vec(), "kept text".into())],
                },
            ];
            store.commit_source_batches_if_changed(&initial).unwrap();

            let mut replacement = [
                Some(SourceBatch {
                    source_path: "source-a".into(),
                    placements: Vec::new(),
                    edges: Vec::new(),
                    activities: Vec::new(),
                    relation_complete: true,
                    len_bytes: None,
                    fingerprint: None,
                    provider_id: None,
                    resume_claim: None,
                    entries: Vec::new(),
                }),
                Some(SourceBatch {
                    source_path: "source-b".into(),
                    placements: Vec::new(),
                    edges: Vec::new(),
                    activities: Vec::new(),
                    relation_complete: true,
                    len_bytes: None,
                    fingerprint: None,
                    provider_id: None,
                    resume_claim: None,
                    entries: vec![(moved, b"m".to_vec(), "moved text".into())],
                }),
                Some(SourceBatch {
                    source_path: "source-c".into(),
                    placements: Vec::new(),
                    edges: Vec::new(),
                    activities: Vec::new(),
                    relation_complete: true,
                    len_bytes: None,
                    fingerprint: None,
                    provider_id: None,
                    resume_claim: None,
                    entries: vec![(kept, b"k".to_vec(), "kept text".into())],
                }),
            ];
            let ordered: Vec<SourceBatch> = order
                .into_iter()
                .map(|index| replacement[index].take().unwrap())
                .collect();
            store.commit_source_batches_if_changed(&ordered).unwrap();
            assert!(store.get(&removed).unwrap().is_none());
            source_state(&store)
        }

        let permutations = [
            [0, 1, 2],
            [0, 2, 1],
            [1, 0, 2],
            [1, 2, 0],
            [2, 0, 1],
            [2, 1, 0],
        ];
        let expected = run(permutations[0]);
        for permutation in permutations.into_iter().skip(1) {
            assert_eq!(run(permutation), expected);
        }
    }

    #[test]
    fn empty_source_scan_tombstones_prior_membership() {
        let store = SqliteStore::open_in_memory().unwrap();
        let id = sid(IdKind::Message, b"becomes-empty");
        let populated = SourceBatch {
            source_path: "empty-later".into(),
            placements: Vec::new(),
            edges: Vec::new(),
            activities: Vec::new(),
            relation_complete: true,
            len_bytes: None,
            fingerprint: None,
            provider_id: None,
            resume_claim: None,
            entries: vec![(id.clone(), b"p".to_vec(), "will disappear".into())],
        };
        store
            .commit_source_batches_if_changed(std::slice::from_ref(&populated))
            .unwrap();
        let empty = SourceBatch {
            source_path: "empty-later".into(),
            placements: Vec::new(),
            edges: Vec::new(),
            activities: Vec::new(),
            relation_complete: true,
            len_bytes: None,
            fingerprint: None,
            provider_id: None,
            resume_claim: None,
            entries: Vec::new(),
        };
        store
            .commit_source_batches_if_changed(std::slice::from_ref(&empty))
            .unwrap();
        assert_eq!(store.count().unwrap(), 0);
        assert!(store.query("disappear", 10).unwrap().is_empty());
    }

    #[test]
    fn duplicate_source_paths_are_rejected() {
        let store = SqliteStore::open_in_memory().unwrap();
        let sources = [
            SourceBatch {
                source_path: "same".into(),
                placements: Vec::new(),
                edges: Vec::new(),
                activities: Vec::new(),
                relation_complete: true,
                len_bytes: None,
                fingerprint: None,
                provider_id: None,
                resume_claim: None,
                entries: Vec::new(),
            },
            SourceBatch {
                source_path: "same".into(),
                placements: Vec::new(),
                edges: Vec::new(),
                activities: Vec::new(),
                relation_complete: true,
                len_bytes: None,
                fingerprint: None,
                provider_id: None,
                resume_claim: None,
                entries: Vec::new(),
            },
        ];
        let err = store
            .commit_source_batches_if_changed(&sources)
            .unwrap_err();
        assert!(matches!(err, PortError::Backend(m) if m.contains("duplicate source paths")));
    }

    #[test]
    fn duplicate_message_error_does_not_disclose_source_path() {
        let store = SqliteStore::open_in_memory().unwrap();
        let id = sid(IdKind::Message, b"duplicate-in-source");
        let private_path = "C:/private/provider/session.jsonl";
        let source = SourceBatch {
            source_path: private_path.into(),
            placements: Vec::new(),
            edges: Vec::new(),
            activities: Vec::new(),
            relation_complete: true,
            len_bytes: None,
            fingerprint: None,
            provider_id: None,
            resume_claim: None,
            entries: vec![
                (id.clone(), b"p".to_vec(), "text".into()),
                (id, b"p".to_vec(), "text".into()),
            ],
        };
        let err = store
            .commit_source_batches_if_changed(std::slice::from_ref(&source))
            .unwrap_err();
        let PortError::Backend(message) = err else {
            panic!("expected backend error");
        };
        assert!(message.contains("duplicate message ids"));
        assert!(!message.contains(private_path));
    }

    #[test]
    fn shared_wire_id_with_conflicting_identity_metadata_is_rejected() {
        let store = SqliteStore::open_in_memory().unwrap();
        let reconstructed = sid(IdKind::Message, b"shared-wire-identity");
        let unstable = StableId::from_wire(reconstructed.as_str()).unwrap();
        assert_ne!(reconstructed, unstable);
        assert_eq!(reconstructed.as_str(), unstable.as_str());

        let sources = [
            SourceBatch {
                source_path: "one".into(),
                placements: Vec::new(),
                edges: Vec::new(),
                activities: Vec::new(),
                relation_complete: true,
                len_bytes: None,
                fingerprint: None,
                provider_id: None,
                resume_claim: None,
                entries: vec![(reconstructed, b"p".to_vec(), "same text".into())],
            },
            SourceBatch {
                source_path: "two".into(),
                placements: Vec::new(),
                edges: Vec::new(),
                activities: Vec::new(),
                relation_complete: true,
                len_bytes: None,
                fingerprint: None,
                provider_id: None,
                resume_claim: None,
                entries: vec![(unstable, b"p".to_vec(), "same text".into())],
            },
        ];
        let err = store
            .commit_source_batches_if_changed(&sources)
            .unwrap_err();
        assert!(
            matches!(err, PortError::Backend(m) if m.contains("conflicting identity metadata"))
        );
    }

    #[test]
    fn separate_batches_reject_conflicting_identity_metadata_without_state_change() {
        let store = SqliteStore::open_in_memory().unwrap();
        let reconstructed = sid(IdKind::Message, b"stored-wire-identity");
        let wire = reconstructed.as_str().to_string();
        let unstable = StableId::from_wire(&wire).unwrap();
        let first = SourceBatch {
            source_path: "first-source".into(),
            placements: Vec::new(),
            edges: Vec::new(),
            activities: Vec::new(),
            relation_complete: true,
            len_bytes: None,
            fingerprint: None,
            provider_id: None,
            resume_claim: None,
            entries: vec![(reconstructed, b"p".to_vec(), "same text".into())],
        };
        assert!(
            store
                .commit_source_batches_if_changed(std::slice::from_ref(&first))
                .unwrap()
        );
        let generation = store.active_generation().unwrap();

        let second = SourceBatch {
            source_path: "second-source".into(),
            placements: Vec::new(),
            edges: Vec::new(),
            activities: Vec::new(),
            relation_complete: true,
            len_bytes: None,
            fingerprint: None,
            provider_id: None,
            resume_claim: None,
            entries: vec![(unstable, b"p".to_vec(), "same text".into())],
        };
        let err = store
            .commit_source_batches_if_changed(std::slice::from_ref(&second))
            .unwrap_err();
        let PortError::Backend(message) = err else {
            panic!("expected backend error");
        };
        assert!(message.contains("conflicting identity metadata"));
        assert!(!message.contains(&wire));
        assert_eq!(store.active_generation().unwrap(), generation);
        assert!(
            store
                .source_message_ids("second-source")
                .unwrap()
                .is_empty()
        );
        let hits = store.query("same", 10).unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].id.stability(), Stability::Reconstructed);
    }

    #[test]
    fn catalog_list_is_sorted_and_limited() {
        let store = SqliteStore::open_in_memory().unwrap();
        let b = sid(IdKind::Message, b"b");
        let a = sid(IdKind::Message, b"a");
        store.put(&b, b"B").unwrap();
        store.put(&a, b"A").unwrap();
        assert_eq!(store.count().unwrap(), 2);
        let all = store.list(10).unwrap();
        assert_eq!(all.len(), 2);
        assert!(all[0].id.as_str() < all[1].id.as_str());
        let one = store.list(1).unwrap();
        assert_eq!(one.len(), 1);
    }

    #[test]
    fn fresh_store_starts_at_generation_zero() {
        let store = SqliteStore::open_in_memory().unwrap();
        assert_eq!(store.active_generation().unwrap(), 0);
        assert_eq!(store.schema_version().unwrap(), SCHEMA_VERSION);
    }

    #[test]
    fn index_batch_commits_and_advances_generation() {
        let store = SqliteStore::open_in_memory().unwrap();
        let a = sid(IdKind::Message, b"a");
        let b = sid(IdKind::Message, b"b");
        let entries = [
            (a.clone(), b"role\talpha".to_vec(), "alpha text".into()),
            (b.clone(), b"role\tbeta".to_vec(), "beta text".into()),
        ];
        let pending = store.begin_index_batch(&entries, &[]).unwrap();
        assert_eq!(pending.base_generation, 0);
        assert_eq!(pending.target_generation, 1);
        // durable intent 已落盘；catalog 仍空。
        assert_eq!(store.count().unwrap(), 0);
        let batch = store.index_batch(&pending.operation_id).unwrap().unwrap();
        assert_eq!(batch.state, "building");
        assert_eq!(batch.durable_point, "intent");
        assert_eq!(batch.operation_digest, pending.operation_digest);

        store.commit_index_batch(&pending, &entries, &[]).unwrap();
        assert_eq!(store.active_generation().unwrap(), 1);
        assert_eq!(store.get(&a).unwrap().unwrap(), b"role\talpha");
        assert_eq!(store.query("alpha", 10).unwrap().len(), 1);
        let batch = store.index_batch(&pending.operation_id).unwrap().unwrap();
        assert_eq!(batch.state, "activated");
        assert_eq!(batch.durable_point, "activated");
    }

    #[test]
    fn commit_rejects_mismatched_payload() {
        let store = SqliteStore::open_in_memory().unwrap();
        let a = sid(IdKind::Message, b"a");
        let b = sid(IdKind::Message, b"b");
        let intended = [(a.clone(), b"x".to_vec(), "x".into())];
        let pending = store.begin_index_batch(&intended, &[]).unwrap();
        // 实际 upsert 含未声明的 b —— 必须拒绝，journal 与数据不能分歧。
        let err = store
            .commit_index_batch(
                &pending,
                &[
                    (a, b"x".to_vec(), "x".into()),
                    (b, b"y".to_vec(), "y".into()),
                ],
                &[],
            )
            .unwrap_err();
        assert!(
            matches!(err, PortError::Backend(m) if m.contains("does not match durable intent"))
        );
        assert_eq!(store.active_generation().unwrap(), 0);
        assert_eq!(store.count().unwrap(), 0);
    }

    #[test]
    fn commit_rejects_tampered_durable_relation_manifest() {
        let store = SqliteStore::open_in_memory().unwrap();
        let session = sid(IdKind::Session, b"manifest-session");
        let document = sid(IdKind::Document, b"manifest-document");
        let message = sid(IdKind::Message, b"manifest-message");
        let message_placement = placement(&session, &document, &message, 0, false, Some((0, 4)));
        let relations = RelationManifests {
            relation_upserts: vec![RelationUpsertManifest::Placement(message_placement)],
            ..RelationManifests::default()
        };
        let pending = store
            .begin_index_batch_with_relations(&[], &[], &relations)
            .unwrap();
        store
            .conn
            .borrow()
            .execute(
                "UPDATE index_batches SET relation_upserts_json = '[]'
                 WHERE operation_id = ?1",
                [&pending.operation_id],
            )
            .unwrap();

        let err = store
            .commit_index_batch_with_relations(&pending, &[], &[], &relations)
            .unwrap_err();
        assert!(
            matches!(err, PortError::Backend(message) if message.contains("does not match durable intent"))
        );
        assert_eq!(store.active_generation().unwrap(), 0);
        assert_eq!(table_count(&store, "message_placements"), 0);
        let batch = store.index_batch(&pending.operation_id).unwrap().unwrap();
        assert_eq!(batch.state, "building");
        assert_eq!(batch.durable_point, "intent");
    }

    #[test]
    fn commit_rejects_tampered_durable_source_replacement_manifest() {
        let store = SqliteStore::open_in_memory().unwrap();
        let relations = RelationManifests {
            source_replacements: vec![SourceReplacementManifest {
                source_path: "manifest-source.jsonl".into(),
                entity_memberships: Vec::new(),
                placement_ids: Vec::new(),
                activity_ids: Vec::new(),
                relation_complete: true,
                len_bytes: None,
                fingerprint: None,
                provider_id: None,
                resume_claim: None,
            }],
            ..RelationManifests::default()
        };
        let pending = store
            .begin_index_batch_with_relations(&[], &[], &relations)
            .unwrap();
        store
            .conn
            .borrow()
            .execute(
                "UPDATE index_batches SET source_replacements_json = '[]'
                 WHERE operation_id = ?1",
                [&pending.operation_id],
            )
            .unwrap();

        let err = store
            .commit_index_batch_with_relations(&pending, &[], &[], &relations)
            .unwrap_err();
        assert!(
            matches!(err, PortError::Backend(message) if message.contains("does not match durable intent"))
        );
        assert_eq!(store.active_generation().unwrap(), 0);
        assert_eq!(table_count(&store, "source_scans"), 0);
        assert_eq!(table_count(&store, "source_relation_scans"), 0);
        let batch = store.index_batch(&pending.operation_id).unwrap().unwrap();
        assert_eq!(batch.state, "building");
        assert_eq!(batch.durable_point, "intent");
    }

    #[test]
    fn commit_rejects_stale_base_generation() {
        let store = SqliteStore::open_in_memory().unwrap();
        let a = sid(IdKind::Message, b"a");
        // 先成功推进到 gen 1。
        let first = [(a.clone(), b"v1".to_vec(), "v1".into())];
        let p1 = store.begin_index_batch(&first, &[]).unwrap();
        store.commit_index_batch(&p1, &first, &[]).unwrap();
        // 伪造一个 base=0 的 pending（模拟旧写者持过期 handle）。
        let stale = PendingIndexBatch {
            operation_id: p1.operation_id.clone(), // 已 activated，非 building
            base_generation: 0,
            target_generation: 1,
            operation_digest: p1.operation_digest.clone(),
        };
        let err = store
            .commit_index_batch(&stale, &[(a, b"v2".to_vec(), "v2".into())], &[])
            .unwrap_err();
        assert!(matches!(err, PortError::Backend(_)));
        assert_eq!(store.active_generation().unwrap(), 1);
    }

    #[test]
    fn recover_aborts_orphan_building_intents() {
        let store = SqliteStore::open_in_memory().unwrap();
        let a = sid(IdKind::Message, b"a");
        let entries = [(a, b"x".to_vec(), "x".into())];
        let pending = store.begin_index_batch(&entries, &[]).unwrap();
        // 模拟崩溃：intent 已 durable，apply 未发生。
        assert_eq!(
            store
                .index_batch(&pending.operation_id)
                .unwrap()
                .unwrap()
                .state,
            "building"
        );
        let n = store.recover_interrupted().unwrap();
        assert_eq!(n, 1);
        let batch = store.index_batch(&pending.operation_id).unwrap().unwrap();
        assert_eq!(batch.state, "aborted");
        assert_eq!(
            batch.error_code.as_deref(),
            Some("interrupted_before_activation")
        );
        // 恢复后 generation 与 catalog 不受影响。
        assert_eq!(store.active_generation().unwrap(), 0);
        assert_eq!(store.count().unwrap(), 0);
        // 幂等：再 recover 0 行。
        assert_eq!(store.recover_interrupted().unwrap(), 0);
    }

    #[test]
    fn rebuild_reprojects_fts_from_catalog_and_advances_generation() {
        let store = SqliteStore::open_in_memory().unwrap();
        let a = sid(IdKind::Message, b"a");
        let b = sid(IdKind::Message, b"b");
        let entries = [
            (
                a.clone(),
                b"user\talpha searchable".to_vec(),
                "alpha searchable".into(),
            ),
            (
                b.clone(),
                b"assistant\tbeta searchable".to_vec(),
                "beta searchable".into(),
            ),
        ];
        store.commit_batch(&entries).unwrap();
        assert_eq!(store.active_generation().unwrap(), 1);

        let n = store.rebuild_index().unwrap();
        assert_eq!(n, 2, "rebuild 应重新索引全部 catalog 实体");
        // rebuild 是显式维护动作：即便内容一致也推进 generation。
        assert_eq!(store.active_generation().unwrap(), 2);
        // 重建后搜索仍可命中，且 id 无损。
        assert_eq!(store.query("alpha", 10).unwrap().len(), 1);
        assert_eq!(store.query("beta", 10).unwrap().len(), 1);
        assert_eq!(store.query("alpha", 10).unwrap()[0].id, a);
    }

    #[test]
    fn rebuild_removes_orphan_fts_rows_not_in_catalog() {
        let store = SqliteStore::open_in_memory().unwrap();
        let real = sid(IdKind::Message, b"real");
        store
            .commit_batch(&[(
                real.clone(),
                b"user\treal body".to_vec(),
                "real body".into(),
            )])
            .unwrap();
        // 直接往 FTS 塞一条 catalog 里没有的孤儿行，模拟索引漂移。
        let orphan = sid(IdKind::Message, b"orphan");
        store.index(&orphan, "orphan drifted body").unwrap();
        assert_eq!(store.query("drifted", 10).unwrap().len(), 1);

        // rebuild 从 catalog 权威重投影：孤儿行应被清除，真实行保留。
        store.rebuild_index().unwrap();
        assert!(
            store.query("drifted", 10).unwrap().is_empty(),
            "rebuild 应清除不在 catalog 中的孤儿 FTS 行"
        );
        assert_eq!(store.query("real", 10).unwrap().len(), 1);
    }

    #[test]
    fn rebuild_indexes_json_payload_text_not_structural_tokens() {
        // H1 regression: ingest/sync writes full JSON payloads. rebuild must
        // index only the `text` field — indexing raw JSON would let
        // structural tokens (`user`, `null`, `sessions`) match every message.
        let store = SqliteStore::open_in_memory().unwrap();
        let a = sid(IdKind::Message, b"json-message-a");
        let payload = serde_json::json!({
            "role": "user",
            "text": "the real searchable body",
            "parent": null,
            "session": "ses-1",
            "sessions": ["ses-1"],
            "timestamp": null,
        })
        .to_string()
        .into_bytes();
        store
            .commit_batch(&[(a.clone(), payload, "one".into())])
            .unwrap();
        // commit 实时路径用调用方传入的 text（此处为 "one"）。
        assert_eq!(store.query("one", 10).unwrap().len(), 1);
        // rebuild 从 catalog 重投影：只索引 JSON 的 text 字段，结构 token 不命中。
        store.rebuild_index().unwrap();
        assert_eq!(store.query("searchable", 10).unwrap().len(), 1);
        assert!(store.query("null", 10).unwrap().is_empty());
        assert!(store.query("sessions", 10).unwrap().is_empty());
        // `ses-1` 里的 `-` 会被 FTS5 当成 NOT 运算符（查询报错而非匹配），
        // 因此用单 token `ses` 断言会话值不被索引。
        assert!(store.query("ses", 10).unwrap().is_empty());
    }

    #[test]
    fn rebuild_restores_search_after_index_data_wiped() {
        // 验证 ADR-0001 的“Catalog 权威、Search 可删除重建”不变量：
        // 直接清空全文索引数据（模拟索引损坏/删除），rebuild 应仅凭权威 catalog 完全恢复搜索。
        let store = SqliteStore::open_in_memory().unwrap();
        let a = sid(IdKind::Message, b"survivor-a");
        let b = sid(IdKind::Message, b"survivor-b");
        store
            .commit_batch(&[
                (
                    a.clone(),
                    b"user\tthe catalog is authoritative".to_vec(),
                    "the catalog is authoritative".into(),
                ),
                (
                    b.clone(),
                    b"assistant\tsearch is a derived projection".to_vec(),
                    "search is a derived projection".into(),
                ),
            ])
            .unwrap();
        assert_eq!(store.query("authoritative", 10).unwrap().len(), 1);

        // 删除全文引擎索引数据（catalog 保持不动，作为权威事实源）。
        {
            let conn = store.conn.borrow();
            conn.execute("DELETE FROM fts", []).unwrap();
            conn.execute("DELETE FROM fts_ids", []).unwrap();
        }
        assert!(
            store.query("authoritative", 10).unwrap().is_empty(),
            "清空后搜索应无结果"
        );
        // catalog 仍完好——rebuild 的权威来源未受影响。
        assert_eq!(store.count().unwrap(), 2);

        let n = store.rebuild_index().unwrap();
        assert_eq!(n, 2, "rebuild 应从 catalog 恢复全部 2 条");
        // 搜索完全恢复，两条都可命中。
        assert_eq!(store.query("authoritative", 10).unwrap().len(), 1);
        assert_eq!(store.query("projection", 10).unwrap().len(), 1);
        // 结果集等价性在 wire id 层面成立——catalog 权威保留的正是 wire 串（其主键）。
        // 注意 stability：fts_ids 边车一并被清空后，身份只能从 catalog wire 串还原，
        // 按域模型（StableId::from_wire）降级为 Unstable，与 catalog-only 的 `list` 读一致。
        // 这落在回滚 runbook“在声明的 identity stability 范围内等价”的语义内：全文索引
        // 数据（含 fts_ids 边车）被删除时，声明的 stability 范围即 Unstable。
        assert_eq!(
            store.query("authoritative", 10).unwrap()[0].id.as_str(),
            a.as_str()
        );
        assert_eq!(
            store.query("projection", 10).unwrap()[0].id.as_str(),
            b.as_str()
        );
        assert_eq!(
            store.query("authoritative", 10).unwrap()[0].id.stability(),
            Stability::Unstable,
            "全文索引数据被整体清空后，身份从 catalog wire 还原为 Unstable"
        );
    }

    #[test]
    fn rebuild_on_empty_catalog_yields_empty_index() {
        let store = SqliteStore::open_in_memory().unwrap();
        let n = store.rebuild_index().unwrap();
        assert_eq!(n, 0);
        assert_eq!(store.active_generation().unwrap(), 1);
        assert!(store.query("anything", 10).unwrap().is_empty());
    }

    #[test]
    fn rebuild_leaves_durable_activated_journal_row() {
        let store = SqliteStore::open_in_memory().unwrap();
        let a = sid(IdKind::Message, b"journal");
        store
            .commit_batch(&[(a, b"user\tjournal body".to_vec(), "journal body".into())])
            .unwrap();
        let before = store.active_generation().unwrap();
        store.rebuild_index().unwrap();
        // 找到本次 rebuild 产生的 activated 批次：target = before + 1。
        let conn = store.conn.borrow();
        let (state, target): (String, i64) = conn
            .query_row(
                "SELECT state, target_generation FROM index_batches
                 ORDER BY target_generation DESC LIMIT 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(state, "activated");
        assert_eq!(target as u64, before + 1);
    }

    #[test]
    fn interrupted_batch_count_observes_without_mutating() {
        let store = SqliteStore::open_in_memory().unwrap();
        let a = sid(IdKind::Message, b"a");
        let entries = [(a, b"x".to_vec(), "x".into())];
        // 干净：0 个待收敛。
        assert_eq!(store.interrupted_batch_count().unwrap(), 0);
        // 写 durable intent 但不 commit（模拟崩溃前）：1 个 building。
        let _pending = store.begin_index_batch(&entries, &[]).unwrap();
        assert_eq!(store.interrupted_batch_count().unwrap(), 1);
        // 只读观测不改状态：再查仍是 1，且 recover 仍能收敛它。
        assert_eq!(store.interrupted_batch_count().unwrap(), 1);
        assert_eq!(store.recover_interrupted().unwrap(), 1);
        assert_eq!(store.interrupted_batch_count().unwrap(), 0);
    }

    #[test]
    fn recover_does_not_touch_activated_batches() {
        let store = SqliteStore::open_in_memory().unwrap();
        let a = sid(IdKind::Message, b"a");
        let entries = [(a, b"x".to_vec(), "x".into())];
        let pending = store.begin_index_batch(&entries, &[]).unwrap();
        store.commit_index_batch(&pending, &entries, &[]).unwrap();
        assert_eq!(store.recover_interrupted().unwrap(), 0);
        assert_eq!(
            store
                .index_batch(&pending.operation_id)
                .unwrap()
                .unwrap()
                .state,
            "activated"
        );
    }

    #[test]
    fn v1_db_migrates_to_v2_with_generation_zero() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("legacy.db");
        let p = path.to_string_lossy().into_owned();
        // 手工造一个 v1 库（只有 catalog + fts，无 store_metadata）。
        {
            let conn = rusqlite::Connection::open(&p).unwrap();
            conn.execute_batch(
                "CREATE TABLE catalog (
                     id TEXT PRIMARY KEY,
                     payload BLOB NOT NULL
                 );
                 CREATE VIRTUAL TABLE fts USING fts5(id UNINDEXED, text);
                 PRAGMA user_version = 1;",
            )
            .unwrap();
            conn.execute(
                "INSERT INTO catalog(id, payload) VALUES('msg_v1_legacy', x'01')",
                [],
            )
            .unwrap();
        }
        // 新二进制打开：自动迁到 v2，数据保留，generation 从 0 起步。
        let store = SqliteStore::open(&p).unwrap();
        assert_eq!(store.schema_version().unwrap(), SCHEMA_VERSION);
        assert_eq!(store.active_generation().unwrap(), 0);
        let id = StableId::from_wire("msg_v1_legacy").unwrap();
        assert_eq!(store.get(&id).unwrap().unwrap(), vec![1u8]);
    }

    #[test]
    fn v7_db_migrates_to_v8_creating_resume_claims_table() {
        // v7 库没有 resume claims 表；打开后升到 v8，表创建且为空——
        // legacy 数据全保留，claims 由 re-sync 回填（ADR-0009）。
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v7.db");
        let p = path.to_string_lossy().into_owned();
        {
            let conn = rusqlite::Connection::open(&p).unwrap();
            create_v6_schema(&conn);
            SqliteStore::migrate_v6_to_v7(&conn).unwrap();
            let version: i64 = conn
                .query_row("PRAGMA user_version", [], |row| row.get(0))
                .unwrap();
            assert_eq!(version, 7);
            let table_exists: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_master
                     WHERE type = 'table' AND name = 'source_session_resume_claims'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(table_exists, 0, "v7 尚无 resume claims 表");
        }
        let store = SqliteStore::open(&p).unwrap();
        assert_eq!(store.schema_version().unwrap(), SCHEMA_VERSION);
        // 无声明/legacy：批量解析恒不可恢复（re-sync 前）。
        let legacy = sid(IdKind::Session, b"v7-legacy-ses");
        let metas = store.resume_of(std::slice::from_ref(&legacy)).unwrap();
        assert_eq!(metas.len(), 1);
        assert!(!metas[0].resume_available);
        assert_eq!(
            metas[0].unavailable_reason.as_deref(),
            Some("no resume metadata claims")
        );
        drop(store);
        let conn = rusqlite::Connection::open(&p).unwrap();
        let table_exists: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master
                 WHERE type = 'table' AND name = 'source_session_resume_claims'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(table_exists, 1);
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM source_session_resume_claims",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 0, "v8 迁移后 claims 表必须为空，等待 re-sync 回填");
    }

    #[test]
    fn injected_v7_to_v8_failure_rolls_back_schema_and_version() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        create_v6_schema(&conn);
        SqliteStore::migrate_v6_to_v7(&conn).unwrap();

        let err = SqliteStore::migrate_v7_to_v8_inner(&conn, true).unwrap_err();
        assert!(
            matches!(err, PortError::Backend(message) if message.contains("injected v7-to-v8"))
        );
        assert!(conn.is_autocommit());
        let version: i64 = conn
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(version, 7);
        let table_exists: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master
                 WHERE type = 'table' AND name = 'source_session_resume_claims'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(table_exists, 0);
    }

    #[test]
    fn v8_to_v9_migration_adds_provider_id_column_non_destructively() {
        // 从真实 v6 schema 迁移到 v8，模拟尚未升级的旧库。
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v8.db");
        let p = path.to_string_lossy().into_owned();
        {
            let conn = rusqlite::Connection::open(&p).unwrap();
            create_v6_schema(&conn);
            SqliteStore::migrate_v6_to_v7(&conn).unwrap();
            SqliteStore::migrate_v7_to_v8(&conn).unwrap();
            let version: i64 = conn
                .query_row("PRAGMA user_version", [], |row| row.get(0))
                .unwrap();
            assert_eq!(version, 8);
            conn.execute(
                "INSERT INTO source_scans(source_path, scanned_at_ms, len_bytes, fingerprint)
                 VALUES('legacy.jsonl', 1, 12, 'legacy-fingerprint')",
                [],
            )
            .unwrap();
            // v9 列尚未存在。
            let cols: Vec<String> = conn
                .prepare("PRAGMA table_info(source_scans)")
                .unwrap()
                .query_map([], |row| row.get::<_, String>(1))
                .unwrap()
                .map(Result::unwrap)
                .collect();
            assert!(!cols.iter().any(|c| c == "provider_id"));
        }
        // 重新打开：触发 v8→v9 迁移。
        let store = SqliteStore::open(&p).unwrap();
        assert_eq!(store.schema_version().unwrap(), SCHEMA_VERSION);
        let conn = rusqlite::Connection::open(&p).unwrap();
        let cols: Vec<String> = conn
            .prepare("PRAGMA table_info(source_scans)")
            .unwrap()
            .query_map([], |row| row.get::<_, String>(1))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        assert!(cols.iter().any(|c| c == "provider_id"));
        // 旧行的 provider_id 为 NULL（回填发生在下次 re-scan）。
        let legacy_provider: Option<String> = conn
            .query_row(
                "SELECT provider_id FROM source_scans WHERE source_path = 'legacy.jsonl'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(legacy_provider, None);
        let legacy_fingerprint: String = conn
            .query_row(
                "SELECT fingerprint FROM source_scans WHERE source_path = 'legacy.jsonl'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(legacy_fingerprint, "legacy-fingerprint");
        // 重新打开同样触发 v10→v11 迁移：Session 元数据搜索投影表必须存在。
        for table in ["session_fts", "session_fts_ids"] {
            let exists: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_master WHERE name = ?1",
                    [table],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(exists, 1, "migrated database must contain {table}");
        }
    }

    #[test]
    fn fresh_db_creates_session_metadata_projection_tables() {
        let store = SqliteStore::open_in_memory().unwrap();
        assert_eq!(store.schema_version().unwrap(), SCHEMA_VERSION);
        let conn = store.conn.borrow();
        for table in ["session_fts", "session_fts_ids"] {
            let exists: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_master
                     WHERE name = ?1",
                    [table],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(exists, 1, "{table} must exist in a fresh database");
        }
        let columns: Vec<String> = conn
            .prepare("PRAGMA table_info(session_fts_ids)")
            .unwrap()
            .query_map([], |row| row.get(1))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        assert_eq!(columns, vec!["session_wire", "fts_rowid"]);
    }

    #[test]
    fn session_metadata_search_is_private_incremental_and_rebuildable() {
        let store = SqliteStore::open_in_memory().unwrap();
        let session = sid(IdKind::Session, b"metadata-session");
        let document = sid(IdKind::Document, b"metadata-document");
        let message = sid(IdKind::Message, b"metadata-message");
        let claim = |native: &str, pair_observed: bool| SourceResumeClaim {
            provider_id: "synthetic".into(),
            session_id: session.as_str().into(),
            provider_session_id: Some(native.into()),
            provider_session_id_state: "resolved".into(),
            original_working_directory: Some("C:/private/worktree".into()),
            original_working_directory_state: "resolved".into(),
            pair_observed,
        };
        let batch = |claim: SourceResumeClaim| SourceBatch {
            source_path: "private-source.jsonl".into(),
            entries: vec![
                entity_entry(&session),
                typed_document_entry(&document),
                typed_message_entry(&message, "first user metadata body"),
            ],
            placements: vec![placement(
                &session,
                &document,
                &message,
                0,
                false,
                Some((0, 5)),
            )],
            edges: Vec::new(),
            activities: Vec::new(),
            relation_complete: true,
            len_bytes: None,
            fingerprint: None,
            provider_id: None,
            resume_claim: Some(claim),
        };

        store
            .commit_source_batches_if_changed(std::slice::from_ref(&batch(claim(
                "native-one",
                true,
            ))))
            .unwrap();
        let text: String = store
            .conn
            .borrow()
            .query_row(
                "SELECT text FROM session_fts WHERE session_wire = ?1",
                [session.as_str()],
                |row| row.get(0),
            )
            .unwrap();
        assert!(text.contains("native-one"));
        assert!(text.contains("C:/private/worktree"));
        assert!(text.contains("first user metadata body"));
        assert!(!text.contains("private-source.jsonl"));

        let native_hits = store.query("native-one", 10).unwrap();
        assert_eq!(native_hits.len(), 1);
        assert_eq!(native_hits[0].id, message);
        assert_eq!(native_hits[0].session_id.as_deref(), Some(session.as_str()));
        assert!(store.query("private-source.jsonl", 10).unwrap().is_empty());

        {
            let conn = store.conn.borrow();
            conn.execute("DELETE FROM session_fts", []).unwrap();
            conn.execute("DELETE FROM session_fts_ids", []).unwrap();
        }
        assert!(store.query("native-one", 10).unwrap().is_empty());
        store.rebuild_index().unwrap();
        assert_eq!(store.query("native-one", 10).unwrap().len(), 1);

        store
            .commit_source_batches_if_changed(std::slice::from_ref(&batch(claim(
                "native-two",
                false,
            ))))
            .unwrap();
        assert!(store.query("native-one", 10).unwrap().is_empty());
        let updated = store.query("native-two", 10).unwrap();
        assert_eq!(updated.len(), 1);
        let updated_text: String = store
            .conn
            .borrow()
            .query_row(
                "SELECT text FROM session_fts WHERE session_wire = ?1",
                [session.as_str()],
                |row| row.get(0),
            )
            .unwrap();
        assert!(!updated_text.contains("C:/private/worktree"));

        // A system-only representative must not suppress the metadata hit: the
        // Application layer removes system messages by default, so the Session
        // candidate remains the user-visible result for a native-id query.
        {
            let conn = store.conn.borrow();
            conn.execute(
                "UPDATE catalog SET payload = ?1 WHERE id = ?2",
                rusqlite::params![
                    serde_json::json!({ "role": "system", "text": "native-two" })
                        .to_string()
                        .into_bytes(),
                    message.as_str(),
                ],
            )
            .unwrap();
        }
        store.rebuild_index().unwrap();
        let system_metadata_hits = store.query("native-two", 10).unwrap();
        assert!(
            system_metadata_hits
                .iter()
                .any(|hit| hit.id == session && hit.session_id.as_deref() == Some(session.as_str()))
        );
    }

    #[test]
    fn metadata_search_indexes_claim_without_user_message_or_placement() {
        let store = SqliteStore::open_in_memory().unwrap();
        let session = sid(IdKind::Session, b"metadata-only-session");
        let claim = SourceResumeClaim {
            provider_id: "synthetic".into(),
            session_id: session.as_str().into(),
            provider_session_id: Some("metadata-only-native".into()),
            provider_session_id_state: "resolved".into(),
            original_working_directory: Some("C:/metadata-only-worktree".into()),
            original_working_directory_state: "resolved".into(),
            pair_observed: true,
        };
        let batch = SourceBatch {
            source_path: "metadata-only-source.jsonl".into(),
            entries: vec![entity_entry(&session)],
            placements: Vec::new(),
            edges: Vec::new(),
            activities: Vec::new(),
            relation_complete: true,
            len_bytes: None,
            fingerprint: None,
            provider_id: None,
            resume_claim: Some(claim),
        };

        store
            .commit_source_batches_if_changed(std::slice::from_ref(&batch))
            .unwrap();

        let hits = store.query("metadata-only-native", 10).unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].id, session);
        assert_eq!(hits[0].session_id.as_deref(), Some(session.as_str()));
        assert!(store.query("C:/metadata-only-worktree", 10).unwrap().len() == 1);
    }

    #[test]
    fn session_metadata_search_conflicting_claims_fail_closed() {
        // 两个 Source 认领同一 canonical Session，但 provider_session_id 不同。
        // `session_search_text` 必须 fail closed：两个 native id 都不进入
        // session_fts 投影（首个 user 消息的 title-like 字段仍在——它不来自声明）。
        let store = SqliteStore::open_in_memory().unwrap();
        let session = sid(IdKind::Session, b"conflict-session");
        let document = sid(IdKind::Document, b"conflict-document");
        let message = sid(IdKind::Message, b"conflict-message");
        let claim = |native: &str| SourceResumeClaim {
            provider_id: "synthetic".into(),
            session_id: session.as_str().into(),
            provider_session_id: Some(native.into()),
            provider_session_id_state: "resolved".into(),
            original_working_directory: Some("C:/conflict-cwd".into()),
            original_working_directory_state: "resolved".into(),
            pair_observed: true,
        };
        let batch = |source_path: &str, native: &str| SourceBatch {
            source_path: source_path.into(),
            entries: vec![
                entity_entry(&session),
                typed_document_entry(&document),
                typed_message_entry(&message, "conflict user body"),
            ],
            placements: vec![placement(&session, &document, &message, 0, false, None)],
            edges: Vec::new(),
            activities: Vec::new(),
            relation_complete: true,
            len_bytes: None,
            fingerprint: None,
            provider_id: None,
            resume_claim: Some(claim(native)),
        };
        store
            .commit_source_batches_if_changed(&[
                batch("conflict-a.jsonl", "conflict-native-alpha"),
                batch("conflict-b.jsonl", "conflict-native-beta"),
            ])
            .unwrap();

        // 任一冲突 native id 都不可检索。
        assert!(
            store.query("conflict-native-alpha", 10).unwrap().is_empty(),
            "conflicting native id alpha must not be indexed"
        );
        assert!(
            store.query("conflict-native-beta", 10).unwrap().is_empty(),
            "conflicting native id beta must not be indexed"
        );
        // session_fts 行仍含首 user 消息投影（不来自冲突声明）。
        let text: String = store
            .conn
            .borrow()
            .query_row(
                "SELECT text FROM session_fts WHERE session_wire = ?1",
                [session.as_str()],
                |row| row.get(0),
            )
            .unwrap();
        assert!(text.contains("conflict user body"));
        assert!(!text.contains("conflict-native-alpha"));
        assert!(!text.contains("conflict-native-beta"));
    }

    #[test]
    fn source_paths_for_provider_returns_only_that_providers_paths() {
        let store = SqliteStore::open_in_memory().unwrap();
        let msg = sid(IdKind::Message, b"provider-diff-msg");
        let ses = sid(IdKind::Session, b"provider-diff-ses");
        let claude_path = "claude-source.jsonl";
        let codex_path = "codex-source.jsonl";
        // discover 批次显式携带 provider_id（显式 sync 留 NULL，discover 不
        // tombstone 根外路径）。
        let claude_batch = SourceBatch {
            source_path: claude_path.into(),
            entries: vec![
                (msg.clone(), b"payload".to_vec(), "text".into()),
                (ses.clone(), b"session".to_vec(), String::new()),
            ],
            placements: Vec::new(),
            edges: Vec::new(),
            activities: Vec::new(),
            relation_complete: true,
            len_bytes: Some(7),
            fingerprint: Some("fp-claude".into()),
            provider_id: Some("claude-code".into()),
            resume_claim: Some(SourceResumeClaim {
                provider_id: "claude-code".into(),
                session_id: ses.as_str().to_string(),
                provider_session_id: Some("claude-native".into()),
                provider_session_id_state: "resolved".into(),
                original_working_directory: None,
                original_working_directory_state: "missing".into(),
                pair_observed: false,
            }),
        };
        let codex_batch = SourceBatch {
            source_path: codex_path.into(),
            entries: vec![
                (msg.clone(), b"payload".to_vec(), "text".into()),
                (ses.clone(), b"session".to_vec(), String::new()),
            ],
            placements: Vec::new(),
            edges: Vec::new(),
            activities: Vec::new(),
            relation_complete: true,
            len_bytes: Some(6),
            fingerprint: Some("fp-codex".into()),
            provider_id: Some("codex".into()),
            resume_claim: Some(SourceResumeClaim {
                provider_id: "codex".into(),
                session_id: ses.as_str().to_string(),
                provider_session_id: Some("codex-native".into()),
                provider_session_id_state: "resolved".into(),
                original_working_directory: None,
                original_working_directory_state: "missing".into(),
                pair_observed: false,
            }),
        };
        store
            .commit_source_batches_if_changed(&[claude_batch, codex_batch])
            .unwrap();
        // discover 批次的 provider_id 落入 source_scans，per-provider diff 可见。
        assert_eq!(
            store.source_paths_for_provider("claude-code").unwrap(),
            vec![claude_path.to_string()]
        );
        assert_eq!(
            store.source_paths_for_provider("codex").unwrap(),
            vec![codex_path.to_string()]
        );
        // 未走 discover 的源（provider_id NULL）对 discover diff 不可见。
        assert_eq!(
            store.source_paths_for_provider("unknown").unwrap(),
            Vec::<String>::new()
        );
    }

    #[test]
    fn source_provider_id_backfill_is_detected_and_never_overwrites() {
        let store = SqliteStore::open_in_memory().unwrap();
        let path = "provider-backfill.jsonl";
        let msg = sid(IdKind::Message, b"provider-backfill-msg");
        let explicit_batch = SourceBatch {
            source_path: path.into(),
            entries: vec![(msg, b"payload".to_vec(), "backfill text".into())],
            placements: Vec::new(),
            edges: Vec::new(),
            activities: Vec::new(),
            relation_complete: true,
            len_bytes: Some(7),
            fingerprint: Some("backfill-fp".into()),
            provider_id: None,
            resume_claim: None,
        };
        assert!(
            store
                .commit_source_batches_if_changed(std::slice::from_ref(&explicit_batch))
                .unwrap()
        );
        assert!(
            store
                .source_paths_for_provider("claude-code")
                .unwrap()
                .is_empty()
        );

        let mut discovered_batch = explicit_batch.clone();
        discovered_batch.provider_id = Some("claude-code".into());
        assert!(
            store
                .commit_source_batches_if_changed(std::slice::from_ref(&discovered_batch))
                .unwrap(),
            "provider-only change must not be treated as current"
        );
        assert_eq!(
            store.source_paths_for_provider("claude-code").unwrap(),
            vec![path.to_string()]
        );
        assert_eq!(
            store
                .backfill_source_provider_ids(&[(path.into(), "codex".into())])
                .unwrap(),
            0,
            "backfill must not overwrite an existing provider"
        );
        assert!(store.source_paths_for_provider("codex").unwrap().is_empty());
    }

    #[test]
    fn backfill_source_provider_ids_associates_explicit_sync_rows() {
        let store = SqliteStore::open_in_memory().unwrap();
        let path = "explicit-provider-backfill.jsonl";
        let batch = SourceBatch {
            source_path: path.into(),
            entries: vec![(
                sid(IdKind::Message, b"explicit-provider-backfill-msg"),
                b"payload".to_vec(),
                "backfill text".into(),
            )],
            placements: Vec::new(),
            edges: Vec::new(),
            activities: Vec::new(),
            relation_complete: true,
            len_bytes: Some(7),
            fingerprint: Some("backfill-fp".into()),
            provider_id: None,
            resume_claim: None,
        };
        store
            .commit_source_batches_if_changed(std::slice::from_ref(&batch))
            .unwrap();

        assert_eq!(
            store
                .backfill_source_provider_ids(&[(path.into(), "claude-code".into())])
                .unwrap(),
            1
        );
        assert_eq!(
            store.source_paths_for_provider("claude-code").unwrap(),
            vec![path.to_string()]
        );
    }

    #[test]
    fn source_paths_requiring_relation_scan_excludes_complete_sources() {
        let store = SqliteStore::open_in_memory().unwrap();
        let path = "relation-recovery.jsonl".to_string();
        let msg = sid(IdKind::Message, b"relation-recovery-msg");
        let batch = SourceBatch {
            source_path: path.clone(),
            entries: vec![(msg, b"payload".to_vec(), "text".into())],
            placements: Vec::new(),
            edges: Vec::new(),
            activities: Vec::new(),
            relation_complete: true,
            len_bytes: Some(7),
            fingerprint: Some("recovery-fp".into()),
            provider_id: None,
            resume_claim: None,
        };
        store
            .commit_source_batches_if_changed(std::slice::from_ref(&batch))
            .unwrap();
        assert!(
            store
                .source_paths_requiring_relation_scan(std::slice::from_ref(&path))
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn source_paths_requiring_relation_scan_reports_incomplete_sources() {
        let store = SqliteStore::open_in_memory().unwrap();
        let path = "relation-recovery-incomplete.jsonl".to_string();
        let msg = sid(IdKind::Message, b"relation-recovery-incomplete-msg");
        let batch = SourceBatch {
            source_path: path.clone(),
            entries: vec![(msg, b"payload".to_vec(), "text".into())],
            placements: Vec::new(),
            edges: Vec::new(),
            activities: Vec::new(),
            relation_complete: false,
            len_bytes: Some(7),
            fingerprint: Some("recovery-incomplete-fp".into()),
            provider_id: None,
            resume_claim: None,
        };
        store
            .commit_source_batches_if_changed(std::slice::from_ref(&batch))
            .unwrap();
        assert_eq!(
            store
                .source_paths_requiring_relation_scan(std::slice::from_ref(&path))
                .unwrap(),
            BTreeSet::from([path])
        );
    }

    #[test]
    fn resume_claim_written_replaced_and_cleared_atomically_with_source() {
        let store = SqliteStore::open_in_memory().unwrap();
        let msg = sid(IdKind::Message, b"resume-claim-msg");
        let ses = sid(IdKind::Session, b"resume-claim-ses");
        let claim = |native: &str| SourceResumeClaim {
            provider_id: "codex".into(),
            session_id: ses.as_str().to_string(),
            provider_session_id: Some(native.into()),
            provider_session_id_state: "resolved".into(),
            original_working_directory: Some("C:/work".into()),
            original_working_directory_state: "resolved".into(),
            pair_observed: true,
        };
        type Entries = Vec<(StableId, Vec<u8>, String)>;
        let batch = |resume_claim: Option<SourceResumeClaim>, entries: Entries| SourceBatch {
            source_path: "resume.jsonl".into(),
            placements: Vec::new(),
            edges: Vec::new(),
            activities: Vec::new(),
            relation_complete: true,
            len_bytes: None,
            fingerprint: None,
            provider_id: None,
            resume_claim,
            entries,
        };
        let populated = batch(
            Some(claim("native-1")),
            vec![
                (msg.clone(), b"payload".to_vec(), "same text".into()),
                (ses.clone(), b"session".to_vec(), String::new()),
            ],
        );

        // 写入：声明随 source 事务落表。
        assert!(
            store
                .commit_source_batches_if_changed(std::slice::from_ref(&populated))
                .unwrap()
        );
        {
            let conn = store.conn.borrow();
            assert_eq!(
                stored_resume_claim(&conn, "resume.jsonl").unwrap(),
                Some(StoredResumeClaim::from_claim(&claim("native-1"))),
            );
        }
        // 同一批次重提交（声明未变）：内容级 no-op，不推进 generation。
        let generation = store.active_generation().unwrap();
        assert!(
            !store
                .commit_source_batches_if_changed(std::slice::from_ref(&populated))
                .unwrap()
        );
        assert_eq!(store.active_generation().unwrap(), generation);

        // 原子替换：只有声明变化也必须走提交路径，旧声明被替换而非残留。
        let replaced = batch(
            Some(claim("native-2")),
            vec![
                (msg.clone(), b"payload".to_vec(), "same text".into()),
                (ses.clone(), b"session".to_vec(), String::new()),
            ],
        );
        assert!(
            store
                .commit_source_batches_if_changed(std::slice::from_ref(&replaced))
                .unwrap()
        );
        {
            let conn = store.conn.borrow();
            assert_eq!(
                stored_resume_claim(&conn, "resume.jsonl").unwrap(),
                Some(StoredResumeClaim::from_claim(&claim("native-2"))),
            );
        }

        // 声明移除：batch 带 None 声明时同事务清除旧行。
        let cleared = batch(
            None,
            vec![(msg.clone(), b"payload".to_vec(), "same text".into())],
        );
        assert!(
            store
                .commit_source_batches_if_changed(std::slice::from_ref(&cleared))
                .unwrap()
        );
        {
            let conn = store.conn.borrow();
            assert_eq!(stored_resume_claim(&conn, "resume.jsonl").unwrap(), None);
        }

        // source 移除（空 scan）：声明随 tombstone 同事务清除。
        assert!(
            store
                .commit_source_batches_if_changed(std::slice::from_ref(&batch(
                    Some(claim("native-3")),
                    vec![
                        (msg.clone(), b"payload".to_vec(), "same text".into()),
                        (ses.clone(), b"session".to_vec(), String::new()),
                    ],
                )))
                .unwrap()
        );
        let retired = batch(None, Vec::new());
        assert!(
            store
                .commit_source_batches_if_changed(std::slice::from_ref(&retired))
                .unwrap()
        );
        {
            let conn = store.conn.borrow();
            assert_eq!(stored_resume_claim(&conn, "resume.jsonl").unwrap(), None);
        }
        assert_eq!(store.count().unwrap(), 0);
    }

    #[test]
    fn resume_of_resolves_batched_claims_in_input_order_without_n_plus_one() {
        // 超过 BATCH_IN_CHUNK 的批量解析：分块 IN 一次调用返回全部，语句数与
        // session 数无关（无 N+1），输出与输入同序。
        let store = SqliteStore::open_in_memory().unwrap();
        let resolved: Vec<(StableId, usize)> = (0..BATCH_IN_CHUNK + 2)
            .map(|i| {
                (
                    sid(IdKind::Session, format!("bulk-resume-{i}").as_bytes()),
                    i,
                )
            })
            .collect();
        let ambiguous = sid(IdKind::Session, b"ambig-ses");
        let missing = sid(IdKind::Session, b"miss-ses");
        let unclaimed = sid(IdKind::Session, b"none-ses");
        {
            let conn = store.conn.borrow();
            for (id, i) in &resolved {
                conn.execute(
                    "INSERT INTO source_session_resume_claims(
                         source_path, session_id, provider_id, provider_session_id,
                         provider_session_id_state, original_working_directory,
                         original_working_directory_state, pair_observed
                     ) VALUES(?1, ?2, 'codex', ?3, 'resolved', ?4, 'resolved', 1)",
                    rusqlite::params![
                        format!("bulk-source-{i}.jsonl"),
                        id.as_str(),
                        format!("native-{i}"),
                        format!("C:/dir-{i}"),
                    ],
                )
                .unwrap();
            }
            conn.execute(
                "INSERT INTO source_session_resume_claims(
                     source_path, session_id, provider_id, provider_session_id,
                     provider_session_id_state, original_working_directory,
                     original_working_directory_state, pair_observed
                 ) VALUES('ambig.jsonl', ?1, 'codex', NULL, 'ambiguous', NULL, 'missing', 0)",
                [ambiguous.as_str()],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO source_session_resume_claims(
                     source_path, session_id, provider_id, provider_session_id,
                     provider_session_id_state, original_working_directory,
                     original_working_directory_state, pair_observed
                 ) VALUES('miss.jsonl', ?1, 'codex', NULL, 'missing', NULL, 'missing', 0)",
                [missing.as_str()],
            )
            .unwrap();
        }

        // 输入刻意乱序（unclaimed 打头 + resolved 倒序混排）。
        let mut input: Vec<StableId> = Vec::new();
        input.push(unclaimed.clone());
        input.extend(resolved.iter().rev().map(|(id, _)| id.clone()));
        input.push(ambiguous.clone());
        input.push(missing.clone());

        let statements = counted_statements(&store, || store.resume_of(&input).unwrap());
        assert_eq!(
            statements, 2,
            "resume_of 必须分块 IN（BATCH_IN_CHUNK 分块），不得逐 session 查询"
        );

        let metas = store.resume_of(&input).unwrap();
        assert_eq!(metas.len(), input.len());
        let expected: BTreeMap<String, usize> = resolved
            .iter()
            .map(|(id, i)| (id.as_str().to_string(), *i))
            .collect();
        for (id, meta) in input.iter().zip(&metas) {
            assert_eq!(&meta.session_id, id, "输出必须与输入同序");
            if id == &unclaimed {
                assert!(!meta.resume_available);
                assert_eq!(meta.provider_id, None);
                assert_eq!(meta.provider_session_id, None);
                assert_eq!(meta.original_working_directory, None);
                assert_eq!(
                    meta.unavailable_reason.as_deref(),
                    Some("no resume metadata claims")
                );
            } else if id == &ambiguous {
                assert!(!meta.resume_available);
                assert_eq!(meta.provider_id.as_deref(), Some("codex"));
                assert_eq!(meta.provider_session_id, None);
                assert_eq!(meta.original_working_directory, None);
                assert_eq!(
                    meta.unavailable_reason.as_deref(),
                    Some("ambiguous provider session id")
                );
            } else if id == &missing {
                assert!(!meta.resume_available);
                assert_eq!(meta.provider_id.as_deref(), Some("codex"));
                assert_eq!(meta.provider_session_id, None);
                assert_eq!(meta.original_working_directory, None);
                assert_eq!(
                    meta.unavailable_reason.as_deref(),
                    Some("provider session id not observed")
                );
            } else {
                let i = expected[id.as_str()];
                assert!(meta.resume_available, "resolved 声明必须可恢复");
                assert_eq!(meta.provider_id.as_deref(), Some("codex"));
                assert_eq!(meta.provider_session_id, Some(format!("native-{i}")));
                assert_eq!(meta.original_working_directory, Some(format!("C:/dir-{i}")));
                assert_eq!(meta.unavailable_reason, None);
            }
        }
    }

    #[test]
    fn resume_of_fails_closed_for_conflicting_source_claims() {
        // 同一 session 的 source-scoped 声明冲突时不得按路径或发现顺序挑选；
        // 固定返回不可恢复且不披露任一冲突值。
        let store = SqliteStore::open_in_memory().unwrap();
        let ses = sid(IdKind::Session, b"multi-source-ses");
        {
            let conn = store.conn.borrow();
            conn.execute(
                "INSERT INTO source_session_resume_claims(
                     source_path, session_id, provider_id, provider_session_id,
                     provider_session_id_state, original_working_directory,
                     original_working_directory_state, pair_observed
                 ) VALUES('b-source.jsonl', ?1, 'codex', 'native-b', 'resolved', 'C:/b', 'resolved', 1)",
                [ses.as_str()],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO source_session_resume_claims(
                     source_path, session_id, provider_id, provider_session_id,
                     provider_session_id_state, original_working_directory,
                     original_working_directory_state, pair_observed
                 ) VALUES('a-source.jsonl', ?1, 'claude-code', 'native-a', 'resolved', 'C:/a', 'resolved', 1)",
                [ses.as_str()],
            )
            .unwrap();
        }
        let metas = store.resume_of(std::slice::from_ref(&ses)).unwrap();
        assert_eq!(metas.len(), 1);
        assert!(!metas[0].resume_available);
        assert_eq!(metas[0].provider_id, None);
        assert_eq!(metas[0].provider_session_id, None);
        assert_eq!(metas[0].original_working_directory, None);
        assert_eq!(
            metas[0].unavailable_reason.as_deref(),
            Some("conflicting resume metadata claims")
        );
    }

    #[test]
    fn resume_of_without_claims_reports_unavailable_not_resumable() {
        // legacy 无声明目录：恒可检索、不可恢复——全字段 None + 明确 reason。
        let store = SqliteStore::open_in_memory().unwrap();
        let ids: Vec<StableId> = (0..3)
            .map(|i| sid(IdKind::Session, format!("legacy-{i}").as_bytes()))
            .collect();
        let metas = store.resume_of(&ids).unwrap();
        for (id, meta) in ids.iter().zip(&metas) {
            assert_eq!(&meta.session_id, id);
            assert!(!meta.resume_available);
            assert_eq!(meta.provider_id, None);
            assert_eq!(meta.provider_session_id, None);
            assert_eq!(meta.original_working_directory, None);
            assert_eq!(
                meta.unavailable_reason.as_deref(),
                Some("no resume metadata claims")
            );
        }
    }

    #[test]
    fn resume_of_hides_cwd_when_pair_not_observed() {
        // Provider Session ID 已 resolved，但 cwd 与 session_id 未配对观测
        // (pair_observed=false)：cwd 必须返回 None，resume 仍可用。
        let store = SqliteStore::open_in_memory().unwrap();
        let ses = sid(IdKind::Session, b"pair-false-ses");
        {
            let conn = store.conn.borrow();
            conn.execute(
                "INSERT INTO source_session_resume_claims(
                     source_path, session_id, provider_id, provider_session_id,
                     provider_session_id_state, original_working_directory,
                     original_working_directory_state, pair_observed
                 ) VALUES('pair.jsonl', ?1, 'codex', 'native-1', 'resolved', 'C:/unpaired', 'resolved', 0)",
                [ses.as_str()],
            )
            .unwrap();
        }
        let metas = store.resume_of(std::slice::from_ref(&ses)).unwrap();
        assert_eq!(metas.len(), 1);
        assert!(metas[0].resume_available);
        assert_eq!(metas[0].provider_id.as_deref(), Some("codex"));
        assert_eq!(metas[0].provider_session_id.as_deref(), Some("native-1"));
        assert_eq!(
            metas[0].original_working_directory, None,
            "未配对观测的 cwd 不得披露"
        );
        assert_eq!(metas[0].unavailable_reason, None);
    }

    #[test]
    fn resume_of_empty_input_returns_empty_without_query() {
        // 空输入短路返回空 Vec，不发起任何 SQL 查询。
        let store = SqliteStore::open_in_memory().unwrap();
        let statements = counted_statements(&store, || {
            let metas = store.resume_of(&[]).unwrap();
            assert!(metas.is_empty());
        });
        assert_eq!(statements, 0, "空输入不得触发数据库查询");
    }

    #[test]
    fn resume_claims_indexed_by_session_id_without_full_scan() {
        // resume_of 分块 IN 查询必须命中 session_id 索引而非全表扫描。
        let store = SqliteStore::open_in_memory().unwrap();
        let ses = sid(IdKind::Session, b"index-probe-ses");
        {
            let conn = store.conn.borrow();
            conn.execute(
                "INSERT INTO source_session_resume_claims(
                     source_path, session_id, provider_id, provider_session_id,
                     provider_session_id_state, original_working_directory,
                     original_working_directory_state, pair_observed
                 ) VALUES('idx.jsonl', ?1, 'codex', 'native-1', 'resolved', 'C:/dir', 'resolved', 1)",
                [ses.as_str()],
            )
            .unwrap();
        }
        let conn = store.conn.borrow();
        let plan: String = conn
            .query_row(
                "EXPLAIN QUERY PLAN
                 SELECT source_path, provider_id, provider_session_id,
                        provider_session_id_state, original_working_directory,
                        original_working_directory_state, pair_observed
                 FROM source_session_resume_claims WHERE session_id = ?1",
                [ses.as_str()],
                |row| row.get::<_, String>(3),
            )
            .unwrap();
        assert!(
            !plan.to_lowercase().contains("scan"),
            "resume 查询必须使用索引而非全表扫描，实际 plan: {plan}"
        );
    }

    // ---- 工具活动（v12）：提交/去重/tombstone/边界/查询 ----

    fn tool_activity_batch(
        source_path: &str,
        message_id: &StableId,
        name: &str,
        kind: &str,
        target: Option<&str>,
        status: &str,
    ) -> SourceBatch {
        SourceBatch {
            source_path: source_path.into(),
            entries: vec![entity_entry(message_id)],
            placements: Vec::new(),
            edges: Vec::new(),
            activities: vec![SourceActivity {
                message_id: message_id.clone(),
                activity: ToolActivity {
                    kind: match kind {
                        "file" => ToolActivityKind::File,
                        "command" => ToolActivityKind::Command,
                        "web" => ToolActivityKind::Web,
                        "query" => ToolActivityKind::Query,
                        _ => ToolActivityKind::Unknown,
                    },
                    actor: ToolActivityActor::Main,
                    name: name.into(),
                    target: target.map(str::to_string),
                    status: match status {
                        "success" => ToolActivityStatus::Success,
                        "error" => ToolActivityStatus::Error,
                        _ => ToolActivityStatus::Unknown,
                    },
                },
            }],
            relation_complete: true,
            len_bytes: Some(1),
            fingerprint: Some(source_path.into()),
            provider_id: None,
            resume_claim: None,
        }
    }

    fn activity_rows(
        store: &SqliteStore,
    ) -> Vec<(String, String, String, String, Option<String>, String)> {
        store
            .conn
            .borrow()
            .prepare("SELECT message_id, kind, actor, name, target, status FROM tool_activities ORDER BY activity_id")
            .unwrap()
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, String>(5)?,
                ))
            })
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
    }

    #[test]
    fn activity_commit_roundtrips_and_survives_unchanged_resync() {
        let store = SqliteStore::open_in_memory().unwrap();
        let message = sid(IdKind::Message, b"activity-msg");
        let source = tool_activity_batch(
            "activity.jsonl",
            &message,
            "Bash",
            "command",
            Some("ls -la"),
            "success",
        );
        assert!(store.commit_source_batches_if_changed(&[source]).unwrap());
        assert_eq!(store.schema_version().unwrap(), SCHEMA_VERSION);

        let rows = activity_rows(&store);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].0, message.as_str());
        assert_eq!(rows[0].1, "command");
        assert_eq!(rows[0].2, "main");
        assert_eq!(rows[0].3, "Bash");
        assert_eq!(rows[0].4.as_deref(), Some("ls -la"));
        assert_eq!(rows[0].5, "success");

        // 内容未变 → 重同步是 no-op（sources_are_current 含活动行/claims 对比）。
        let source = tool_activity_batch(
            "activity.jsonl",
            &message,
            "Bash",
            "command",
            Some("ls -la"),
            "success",
        );
        assert!(!store.commit_source_batches_if_changed(&[source]).unwrap());
        assert_eq!(activity_rows(&store).len(), 1);
    }

    #[test]
    fn activity_commit_is_idempotent_across_fingerprint_change() {
        // 指纹变化（重解析）但活动事实相同：幂等重写，不产生重复行。
        let store = SqliteStore::open_in_memory().unwrap();
        let message = sid(IdKind::Message, b"activity-msg");
        let first = tool_activity_batch(
            "activity.jsonl",
            &message,
            "Bash",
            "command",
            Some("ls -la"),
            "success",
        );
        assert!(store.commit_source_batches_if_changed(&[first]).unwrap());
        let mut second = tool_activity_batch(
            "activity.jsonl",
            &message,
            "Bash",
            "command",
            Some("ls -la"),
            "success",
        );
        second.fingerprint = Some("changed-fingerprint".into());
        assert!(store.commit_source_batches_if_changed(&[second]).unwrap());
        assert_eq!(activity_rows(&store).len(), 1);
    }

    #[test]
    fn activity_target_is_bounded_before_storage() {
        let store = SqliteStore::open_in_memory().unwrap();
        let message = sid(IdKind::Message, b"activity-bound");
        let long_target = "x".repeat(TOOL_ACTIVITY_TARGET_MAX_CHARS + 100);
        let source = tool_activity_batch(
            "bound.jsonl",
            &message,
            "Bash",
            "command",
            Some(&long_target),
            "success",
        );
        store.commit_source_batches_if_changed(&[source]).unwrap();
        let rows = activity_rows(&store);
        assert_eq!(rows.len(), 1);
        let stored = rows[0].4.clone().unwrap();
        assert_eq!(stored.chars().count(), TOOL_ACTIVITY_TARGET_MAX_CHARS);
    }

    #[test]
    fn complete_rescan_removes_dropped_activities_and_empty_scan_tombstones_all() {
        let store = SqliteStore::open_in_memory().unwrap();
        let msg_a = sid(IdKind::Message, b"act-a");
        let msg_b = sid(IdKind::Message, b"act-b");
        let batch = |entries: Vec<(StableId, Vec<u8>, String)>, activities: Vec<SourceActivity>| {
            SourceBatch {
                source_path: "rescan.jsonl".into(),
                entries,
                placements: Vec::new(),
                edges: Vec::new(),
                activities,
                relation_complete: true,
                len_bytes: Some(1),
                fingerprint: Some("rescan-fp".into()),
                provider_id: None,
                resume_claim: None,
            }
        };
        let activity = |message_id: &StableId, name: &str| SourceActivity {
            message_id: message_id.clone(),
            activity: ToolActivity {
                kind: ToolActivityKind::Command,
                actor: ToolActivityActor::Main,
                name: name.into(),
                target: Some(format!("cmd-{name}")),
                status: ToolActivityStatus::Success,
            },
        };
        let first = batch(
            vec![entity_entry(&msg_a), entity_entry(&msg_b)],
            vec![activity(&msg_a, "Bash"), activity(&msg_b, "Read")],
        );
        assert!(store.commit_source_batches_if_changed(&[first]).unwrap());
        assert_eq!(activity_rows(&store).len(), 2);

        // 完整重扫只保留 Read：Bash 活动被 tombstone（claim 消失且无他人认领）。
        let second = batch(vec![entity_entry(&msg_b)], vec![activity(&msg_b, "Read")]);
        assert!(store.commit_source_batches_if_changed(&[second]).unwrap());
        let rows = activity_rows(&store);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].3, "Read");

        // 空源（整源清空，relation_complete=true）：全部活动 tombstone。
        let empty = batch(Vec::new(), Vec::new());
        assert!(store.commit_source_batches_if_changed(&[empty]).unwrap());
        assert!(activity_rows(&store).is_empty());
    }

    #[test]
    fn incomplete_scan_unions_activities_without_tombstoning() {
        let store = SqliteStore::open_in_memory().unwrap();
        let msg_a = sid(IdKind::Message, b"inc-a");
        let msg_b = sid(IdKind::Message, b"inc-b");
        let batch = |entries: Vec<(StableId, Vec<u8>, String)>,
                     activities: Vec<SourceActivity>,
                     complete: bool| {
            SourceBatch {
                source_path: "incomplete.jsonl".into(),
                entries,
                placements: Vec::new(),
                edges: Vec::new(),
                activities,
                relation_complete: complete,
                len_bytes: Some(1),
                fingerprint: Some("inc-fp".into()),
                provider_id: None,
                resume_claim: None,
            }
        };
        let activity = |message_id: &StableId, name: &str| SourceActivity {
            message_id: message_id.clone(),
            activity: ToolActivity {
                kind: ToolActivityKind::File,
                actor: ToolActivityActor::Main,
                name: name.into(),
                target: None,
                status: ToolActivityStatus::Success,
            },
        };
        let first = batch(
            vec![entity_entry(&msg_a)],
            vec![activity(&msg_a, "Read")],
            true,
        );
        assert!(store.commit_source_batches_if_changed(&[first]).unwrap());

        // 不完整重扫（skipped>0 → relation_complete=false）：union，不删旧活动。
        let second = batch(
            vec![entity_entry(&msg_b)],
            vec![activity(&msg_b, "Grep")],
            false,
        );
        assert!(store.commit_source_batches_if_changed(&[second]).unwrap());
        let rows = activity_rows(&store);
        assert_eq!(rows.len(), 2, "不完整扫描必须保留未观察到的活动");
        let names: Vec<&str> = rows.iter().map(|row| row.3.as_str()).collect();
        assert!(names.contains(&"Read") && names.contains(&"Grep"));
    }

    #[test]
    fn identical_activity_from_two_sources_dedups_into_one_row() {
        let store = SqliteStore::open_in_memory().unwrap();
        let message = sid(IdKind::Message, b"shared-act");
        let first = tool_activity_batch(
            "source-a.jsonl",
            &message,
            "Bash",
            "command",
            Some("ls"),
            "success",
        );
        let second = tool_activity_batch(
            "source-b.jsonl",
            &message,
            "Bash",
            "command",
            Some("ls"),
            "success",
        );
        assert!(
            store
                .commit_source_batches_if_changed(&[first, second])
                .unwrap()
        );
        assert_eq!(
            activity_rows(&store).len(),
            1,
            "同事实同锚点 → 同一行，两份 claim"
        );

        // 一个源消失（空批）不删除仍被另一源认领的活动。
        let empty = SourceBatch {
            source_path: "source-a.jsonl".into(),
            entries: Vec::new(),
            placements: Vec::new(),
            edges: Vec::new(),
            activities: Vec::new(),
            relation_complete: true,
            len_bytes: Some(0),
            fingerprint: Some("empty-a".into()),
            provider_id: None,
            resume_claim: None,
        };
        assert!(store.commit_source_batches_if_changed(&[empty]).unwrap());
        assert_eq!(activity_rows(&store).len(), 1);

        // 两个源都消失 → 行删除。
        let empty_b = SourceBatch {
            source_path: "source-b.jsonl".into(),
            entries: Vec::new(),
            placements: Vec::new(),
            edges: Vec::new(),
            activities: Vec::new(),
            relation_complete: true,
            len_bytes: Some(0),
            fingerprint: Some("empty-b".into()),
            provider_id: None,
            resume_claim: None,
        };
        assert!(store.commit_source_batches_if_changed(&[empty_b]).unwrap());
        assert!(activity_rows(&store).is_empty());
    }

    #[test]
    fn distinct_activity_facts_on_one_message_coexist_across_sources() {
        // activity_id 由事实内容寻址：同一消息上不同事实 → 不同行，两源各自认领。
        // （同消息同事实 → 同一行 + 双 claim，见 identical_activity_from_two_sources。）
        let store = SqliteStore::open_in_memory().unwrap();
        let message = sid(IdKind::Message, b"conflict-act");
        let mut first = tool_activity_batch(
            "source-a.jsonl",
            &message,
            "Bash",
            "command",
            Some("ls"),
            "success",
        );
        first.entries = vec![entity_entry(&message)];
        first.fingerprint = Some("fp-a".into());
        let mut second = tool_activity_batch(
            "source-b.jsonl",
            &message,
            "Bash",
            "command",
            Some("ls -la"),
            "success",
        );
        second.entries = vec![entity_entry(&message)];
        second.fingerprint = Some("fp-b".into());
        assert!(
            store
                .commit_source_batches_if_changed(&[first, second])
                .unwrap()
        );
        let rows = activity_rows(&store);
        assert_eq!(rows.len(), 2, "不同事实 → 两行（锚点相同、事实不同）");
        let targets: Vec<Option<&str>> = rows.iter().map(|row| row.4.as_deref()).collect();
        assert!(targets.contains(&Some("ls")) && targets.contains(&Some("ls -la")));
    }

    #[test]
    fn activity_anchored_to_non_message_is_rejected() {
        let store = SqliteStore::open_in_memory().unwrap();
        let session = sid(IdKind::Session, b"not-a-message");
        let source = tool_activity_batch(
            "bad-anchor.jsonl",
            &session,
            "Bash",
            "command",
            None,
            "success",
        );
        let error = store
            .commit_source_batches_if_changed(&[source])
            .unwrap_err();
        assert!(matches!(error, PortError::Backend(_)));
    }

    // ---- 工具活动保留策略（v12）：source 退役级联 + 孤儿扫描/修剪 ----

    #[test]
    fn source_removal_clears_activities_and_membership_in_same_transaction() {
        // 保留策略核心不变量（级联验证）：source 退役（空完整 scan）时，
        // 其活动的 tool_activities 行与 tool_activity_membership 行在同一
        // 提交内消失——投影行绝不比 catalog 事实活得更久，无需事后清理。
        let store = SqliteStore::open_in_memory().unwrap();
        let message = sid(IdKind::Message, b"retire-activity");
        let full = tool_activity_batch(
            "retire-activity.jsonl",
            &message,
            "Bash",
            "command",
            Some("ls"),
            "success",
        );
        assert!(store.commit_source_batches_if_changed(&[full]).unwrap());
        assert_eq!(activity_rows(&store).len(), 1);
        {
            let conn = store.conn.borrow();
            let claims: i64 = conn
                .query_row("SELECT COUNT(*) FROM tool_activity_membership", [], |row| {
                    row.get(0)
                })
                .unwrap();
            assert_eq!(claims, 1, "活动行必须有对应 claim");
        }

        let empty = SourceBatch {
            source_path: "retire-activity.jsonl".into(),
            entries: Vec::new(),
            placements: Vec::new(),
            edges: Vec::new(),
            activities: Vec::new(),
            relation_complete: true,
            len_bytes: Some(0),
            fingerprint: Some("empty".into()),
            provider_id: None,
            resume_claim: None,
        };
        assert!(store.commit_source_batches_if_changed(&[empty]).unwrap());
        assert!(store.get(&message).unwrap().is_none(), "消息随 source 退役");
        assert!(
            activity_rows(&store).is_empty(),
            "活动行必须与消息在同一提交内删除"
        );
        {
            let conn = store.conn.borrow();
            let claims: i64 = conn
                .query_row("SELECT COUNT(*) FROM tool_activity_membership", [], |row| {
                    row.get(0)
                })
                .unwrap();
            assert_eq!(claims, 0, "成员行必须与 source 在同一提交内删除");
        }
        assert_eq!(
            store.orphaned_activity_counts().unwrap(),
            (0, 0),
            "级联后的库无孤儿行"
        );
    }

    #[test]
    fn orphaned_activity_scan_reports_activity_whose_message_was_removed() {
        // 漂移状态可通过公共 API 达到：完整重扫退役了消息但仍观察其活动
        // （不一致的 source 投影）→ 活动行与 claim 留存、锚点悬空。
        // 扫描必须报出，修剪必须可确定性清除。
        let store = SqliteStore::open_in_memory().unwrap();
        let message = sid(IdKind::Message, b"orphan-msg");
        let first = tool_activity_batch("orphan.jsonl", &message, "Read", "file", None, "success");
        assert!(store.commit_source_batches_if_changed(&[first]).unwrap());

        let mut second =
            tool_activity_batch("orphan.jsonl", &message, "Read", "file", None, "success");
        second.entries = Vec::new();
        second.fingerprint = Some("rescan-fp".into());
        assert!(store.commit_source_batches_if_changed(&[second]).unwrap());
        assert!(store.get(&message).unwrap().is_none(), "消息已退役");
        assert_eq!(activity_rows(&store).len(), 1, "活动行仍在（锚点悬空）");
        let (activities, memberships) = store.orphaned_activity_counts().unwrap();
        assert_eq!(activities, 1, "悬空活动是孤儿");
        assert_eq!(memberships, 0, "活动行还在，其 claim 不算孤儿");
    }

    #[test]
    fn orphaned_membership_scan_reports_dangling_claim() {
        // 指向不存在活动的成员行（悬空 claim）：写路径同事务保证无法产生，
        // 只能由裸批/历史漂移造成；直接 SQL 构造并验证扫描报出。
        let store = SqliteStore::open_in_memory().unwrap();
        {
            let conn = store.conn.borrow();
            conn.execute(
                "INSERT INTO tool_activity_membership(source_path, activity_id)
                 VALUES('ghost.jsonl', 'act_v1_deadbeefdeadbeef')",
                [],
            )
            .unwrap();
        }
        let (activities, memberships) = store.orphaned_activity_counts().unwrap();
        assert_eq!(activities, 0);
        assert_eq!(memberships, 1);
    }

    #[test]
    fn purge_orphaned_activities_removes_only_dangling_projection_rows() {
        // 修剪只删悬空行：合法活动、合法 claim、catalog 全部原样保留。
        let store = SqliteStore::open_in_memory().unwrap();
        let live_msg = sid(IdKind::Message, b"live-msg");
        let live = tool_activity_batch(
            "live.jsonl",
            &live_msg,
            "Bash",
            "command",
            Some("ls"),
            "success",
        );
        assert!(store.commit_source_batches_if_changed(&[live]).unwrap());

        // 孤儿活动：消息退役、活动留存（见 orphaned_activity_scan_*）。
        let orphan_msg = sid(IdKind::Message, b"purge-orphan-msg");
        let orphaned =
            tool_activity_batch("orphan.jsonl", &orphan_msg, "Read", "file", None, "success");
        assert!(store.commit_source_batches_if_changed(&[orphaned]).unwrap());
        let mut rescan =
            tool_activity_batch("orphan.jsonl", &orphan_msg, "Read", "file", None, "success");
        rescan.entries = Vec::new();
        rescan.fingerprint = Some("rescan-fp".into());
        assert!(store.commit_source_batches_if_changed(&[rescan]).unwrap());

        // 孤儿成员：指向不存在活动的 claim。
        {
            let conn = store.conn.borrow();
            conn.execute(
                "INSERT INTO tool_activity_membership(source_path, activity_id)
                 VALUES('ghost.jsonl', 'act_v1_deadbeefdeadbeef')",
                [],
            )
            .unwrap();
        }
        assert_eq!(store.orphaned_activity_counts().unwrap(), (1, 1));

        let generation_before = store.active_generation().unwrap();
        let (removed_activities, removed_memberships) = store.purge_orphaned_activities().unwrap();
        // 成员行删除数含孤儿活动的 claim 级联：orphan.jsonl 对已删活动的
        // claim 随修剪一并清除，加预悬空的 ghost claim 共 2 行。
        assert_eq!((removed_activities, removed_memberships), (1, 2));
        assert_eq!(
            store.orphaned_activity_counts().unwrap(),
            (0, 0),
            "修剪后无孤儿行"
        );
        // 合法投影原样保留。
        let rows = activity_rows(&store);
        assert_eq!(rows.len(), 1, "合法活动行必须保留");
        assert_eq!(rows[0].0, live_msg.as_str());
        {
            let conn = store.conn.borrow();
            let live_claims: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM tool_activity_membership
                     WHERE source_path = 'live.jsonl'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(live_claims, 1, "合法 claim 必须保留");
        }
        assert_eq!(
            store.active_generation().unwrap(),
            generation_before + 1,
            "修剪走 rebuild 同款 generation 纪律：恰好推进一次"
        );

        // 幂等收敛：无孤儿时修剪是 no-op，不再推进 generation。
        let (again_activities, again_memberships) = store.purge_orphaned_activities().unwrap();
        assert_eq!((again_activities, again_memberships), (0, 0));
        assert_eq!(
            store.active_generation().unwrap(),
            generation_before + 1,
            "空跑修剪不得产生 generation churn"
        );
    }

    #[test]
    fn purge_leaves_catalog_fts_and_search_projections_unchanged() {
        // 修剪的不变量：除悬空投影行外，catalog、消息 FTS、session 元数据
        // 投影、合法 claim 逐行不变——修剪绝不能借机改写权威数据。
        let store = SqliteStore::open_in_memory().unwrap();
        let session = sid(IdKind::Session, b"invariant-session");
        let document = sid(IdKind::Document, b"invariant-document");
        let message = sid(IdKind::Message, b"invariant-message");
        let full = source_batch(
            "invariant.jsonl",
            vec![
                entity_entry(&session),
                typed_document_entry(&document),
                typed_message_entry(&message, "invariant searchable body"),
            ],
            vec![placement(&session, &document, &message, 0, false, None)],
            Vec::new(),
            true,
        );
        assert!(store.commit_source_batches_if_changed(&[full]).unwrap());
        assert!(store.query("invariant", 10).unwrap().len() == 1);

        // 孤儿活动（锚点悬空）+ 孤儿成员（claim 悬空）。
        {
            let conn = store.conn.borrow();
            conn.execute(
                "INSERT INTO tool_activities(
                     activity_id, message_id, kind, actor, name, target, status
                 ) VALUES('act_v1_orphan', 'msg_v1_deadbeefdeadbeef',
                          'command', 'main', 'Ghost', NULL, 'success')",
                [],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO tool_activity_membership(source_path, activity_id)
                 VALUES('ghost.jsonl', 'act_v1_ghostclaim')",
                [],
            )
            .unwrap();
        }
        let catalog_before = store.list(usize::MAX).unwrap();
        let session_fts_snapshot = |store: &SqliteStore| -> Vec<(String, String)> {
            let conn = store.conn.borrow();
            let mut stmt = conn
                .prepare("SELECT session_wire, text FROM session_fts ORDER BY session_wire")
                .unwrap();
            stmt.query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
        };
        let session_fts_before = session_fts_snapshot(&store);
        assert!(!session_fts_before.is_empty(), "session 元数据投影必须有行");

        let (removed_activities, removed_memberships) = store.purge_orphaned_activities().unwrap();
        assert_eq!((removed_activities, removed_memberships), (1, 1));

        // catalog 逐行不变（权威数据）。
        assert_eq!(store.list(usize::MAX).unwrap(), catalog_before);
        // 消息 FTS 不变：既有查询仍命中且仅命中同一集合。
        assert_eq!(store.query("invariant", 10).unwrap().len(), 1);
        assert!(store.query("Ghost", 10).unwrap().is_empty());
        // session 元数据投影逐行不变。
        let session_fts_after = session_fts_snapshot(&store);
        assert_eq!(session_fts_after, session_fts_before);
        assert_eq!(
            store.orphaned_activity_counts().unwrap(),
            (0, 0),
            "修剪后无孤儿行"
        );
    }

    // ---- 活动 facet 查询（v12）----

    #[test]
    fn query_faceted_default_matches_plain_query() {
        let store = SqliteStore::open_in_memory().unwrap();
        let message = sid(IdKind::Message, b"facet-msg");
        let source = tool_activity_batch(
            "facet.jsonl",
            &message,
            "Bash",
            "command",
            Some("ls"),
            "success",
        );
        store.commit_source_batches_if_changed(&[source]).unwrap();
        let plain = store.query("msg_v1", 10).unwrap();
        assert_eq!(
            plain.len(),
            1,
            "查询必须实际命中（FTS 正文是 wire id 文本）"
        );
        let faceted = store
            .query_faceted(
                SearchQuery {
                    text: "msg_v1",
                    filters: &SearchFilters::EMPTY,
                },
                10,
                &SearchFacets::default(),
            )
            .unwrap();
        assert_eq!(plain, faceted);
    }

    #[test]
    fn query_faceted_filters_by_tool_kind_and_name() {
        let store = SqliteStore::open_in_memory().unwrap();
        let msg_a = sid(IdKind::Message, b"facet-bash");
        let msg_b = sid(IdKind::Message, b"facet-read");
        let batch = |entries: Vec<(StableId, Vec<u8>, String)>, activities: Vec<SourceActivity>| {
            SourceBatch {
                source_path: "facet-two.jsonl".into(),
                entries,
                placements: Vec::new(),
                edges: Vec::new(),
                activities,
                relation_complete: true,
                len_bytes: Some(1),
                fingerprint: Some("facet-two-fp".into()),
                provider_id: None,
                resume_claim: None,
            }
        };
        let activity = |message_id: &StableId, kind: ToolActivityKind, name: &str| SourceActivity {
            message_id: message_id.clone(),
            activity: ToolActivity {
                kind,
                actor: ToolActivityActor::Main,
                name: name.into(),
                target: None,
                status: ToolActivityStatus::Success,
            },
        };
        let source = batch(
            vec![entity_entry(&msg_a), entity_entry(&msg_b)],
            vec![
                activity(&msg_a, ToolActivityKind::Command, "Bash"),
                activity(&msg_b, ToolActivityKind::File, "Read"),
            ],
        );
        store.commit_source_batches_if_changed(&[source]).unwrap();

        let by_kind = store
            .query_faceted(
                SearchQuery {
                    text: "msg_v1",
                    filters: &SearchFilters::EMPTY,
                },
                10,
                &SearchFacets {
                    tool_kind: Some("command".into()),
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(by_kind.len(), 1);
        assert_eq!(by_kind[0].id.as_str(), msg_a.as_str());

        let by_name = store
            .query_faceted(
                SearchQuery {
                    text: "msg_v1",
                    filters: &SearchFilters::EMPTY,
                },
                10,
                &SearchFacets {
                    tool_name: Some("Read".into()),
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(by_name.len(), 1);
        assert_eq!(by_name[0].id.as_str(), msg_b.as_str());

        let none = store
            .query_faceted(
                SearchQuery {
                    text: "msg_v1",
                    filters: &SearchFilters::EMPTY,
                },
                10,
                &SearchFacets {
                    tool_name: Some("Grep".into()),
                    ..Default::default()
                },
            )
            .unwrap();
        assert!(none.is_empty());
    }

    #[test]
    fn query_faceted_filters_sidechains_on_indexed_columns() {
        let store = SqliteStore::open_in_memory().unwrap();
        let session = sid(IdKind::Session, b"facet-session");
        let document = sid(IdKind::Document, b"facet-doc");
        let main_msg = sid(IdKind::Message, b"facet-main");
        let side_msg = sid(IdKind::Message, b"facet-side");
        let main_placement = MessagePlacement::new(
            session.clone(),
            document.clone(),
            main_msg.clone(),
            0,
            false,
            None,
        );
        let side_placement = MessagePlacement::new(
            session.clone(),
            document.clone(),
            side_msg.clone(),
            1,
            true,
            None,
        );
        let source = SourceBatch {
            source_path: "facet-sidechain.jsonl".into(),
            entries: vec![
                entity_entry(&main_msg),
                entity_entry(&side_msg),
                entity_entry(&session),
                entity_entry(&document),
            ],
            placements: vec![main_placement, side_placement],
            edges: Vec::new(),
            activities: Vec::new(),
            relation_complete: true,
            len_bytes: Some(1),
            fingerprint: Some("facet-sidechain-fp".into()),
            provider_id: None,
            resume_claim: None,
        };
        store.commit_source_batches_if_changed(&[source]).unwrap();

        let main_only = store
            .query_faceted(
                SearchQuery {
                    text: "msg_v1",
                    filters: &SearchFilters::EMPTY,
                },
                10,
                &SearchFacets {
                    sidechain: SidechainFacet::MainOnly,
                    ..Default::default()
                },
            )
            .unwrap();
        let ids: Vec<&str> = main_only.iter().map(|hit| hit.id.as_str()).collect();
        assert!(ids.contains(&main_msg.as_str()));
        assert!(!ids.contains(&side_msg.as_str()));

        let subagent_only = store
            .query_faceted(
                SearchQuery {
                    text: "msg_v1",
                    filters: &SearchFilters::EMPTY,
                },
                10,
                &SearchFacets {
                    sidechain: SidechainFacet::SubagentOnly,
                    ..Default::default()
                },
            )
            .unwrap();
        let ids: Vec<&str> = subagent_only.iter().map(|hit| hit.id.as_str()).collect();
        assert_eq!(ids, vec![side_msg.as_str()]);
    }

    #[test]
    fn v7_catalog_migrates_to_v12_adding_activity_tables() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v7.db");
        let p = path.to_string_lossy().into_owned();
        // 手工造一个 v7 库（最小关系 schema），打开后应迁到 v12 并补建活动表。
        {
            let conn = rusqlite::Connection::open(&p).unwrap();
            conn.execute_batch(
                "CREATE TABLE catalog (id TEXT PRIMARY KEY, payload BLOB NOT NULL);
                 CREATE VIRTUAL TABLE fts USING fts5(id UNINDEXED, text);
                 CREATE TABLE store_metadata (
                     singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                     active_generation INTEGER NOT NULL
                 );
                 INSERT INTO store_metadata(singleton, active_generation) VALUES(1, 3);
                 CREATE TABLE fts_ids (wire_id TEXT PRIMARY KEY, id_json TEXT NOT NULL UNIQUE);
                 CREATE TABLE source_membership (
                     source_path TEXT NOT NULL,
                     message_id TEXT NOT NULL,
                     document_id TEXT,
                     PRIMARY KEY(source_path, message_id)
                 );
                 CREATE TABLE source_scans (
                     source_path TEXT PRIMARY KEY,
                     scanned_at_ms INTEGER NOT NULL,
                     len_bytes INTEGER,
                     fingerprint TEXT
                 );
                 PRAGMA user_version = 7;",
            )
            .unwrap();
        }
        let store = SqliteStore::open(&p).unwrap();
        assert_eq!(store.schema_version().unwrap(), SCHEMA_VERSION);
        assert_eq!(store.active_generation().unwrap(), 3);
        // 活动表已建好且可写（直接 SQL 写入验证，不依赖完整 v7 关系提交路径）。
        let conn = store.conn.borrow();
        conn.execute(
            "INSERT INTO tool_activities(
                 activity_id, message_id, kind, actor, name, target, status
             ) VALUES('act_v1_test', 'msg_v1_migrated', 'command', 'main', 'Bash', 'ls', 'success')",
            [],
        )
        .unwrap();
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM tool_activities", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 1);
        drop(conn);
    }
}
