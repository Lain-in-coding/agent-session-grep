//! Cursor provider adapter.
//!
//! Parses Cursor chat history from the VS Code workspaceStorage `state.vscdb`
//! SQLite file (ItemTable KV store). The adapter receives the SQLite file as a
//! byte stream, writes it to a temporary file, and opens it read-only
//! (SQLITE_OPEN_READONLY + busy_timeout), same as the opencode adapter.
//!
//! Format evidence: hstry (MIT) `adapters/cursor/adapter.ts`:
//! - key `workbench.panel.aichat.view.aichat.chatdata` → JSON document with
//!   `tabs`, each tab holding `bubbles` (type/text/rawText/timingInfo.startTime)
//! - key `aiService.prompts` → JSON array of `{prompt, response, createdAt,
//!   conversationId}` records, grouped into conversations by conversationId

use std::io::Write;
use std::sync::atomic::{AtomicU64, Ordering};

use agent_session_grep_ports::{
    AdapterManifest, CanonicalEventSink, Confidence, MessageEvent, MetadataResolution, ParseReport,
    ProbeResult, ProviderAdapter, ProviderError, manifest_for,
};
use rusqlite::{Connection, OpenFlags, params};

/// Variant id surfaced in probe results.
const VARIANT_ID: &str = "cursor/vscdb-chat-v1";

/// SQLite magic header: every SQLite database starts with "SQLite format 3\0".
const SQLITE_MAGIC: &[u8] = b"SQLite format 3\0";

/// ItemTable key holding the chat tabs JSON document.
const CHAT_DATA_KEY: &str = "workbench.panel.aichat.view.aichat.chatdata";

/// ItemTable key holding the flat prompts history JSON array.
const PROMPTS_KEY: &str = "aiService.prompts";

/// Cursor adapter: parses `state.vscdb` (SQLite ItemTable KV store).
///
/// The adapter writes the byte stream to a temp file and opens it read-only,
/// because rusqlite requires a file path (no in-memory deserialize in 0.40).
/// The temp file is cleaned up by the OS.
pub struct CursorAdapter;

impl CursorAdapter {
    pub fn new() -> Self {
        Self
    }
}

impl Default for CursorAdapter {
    fn default() -> Self {
        Self::new()
    }
}

/// `workbench.panel.aichat.view.aichat.chatdata` payload.
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct ChatData {
    #[serde(default)]
    tabs: Vec<Tab>,
}

/// One chat tab: a conversation with its message bubbles.
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct Tab {
    id: Option<String>,
    created_at: Option<i64>,
    #[serde(default)]
    bubbles: Vec<Bubble>,
}

/// One chat bubble: a single user/assistant message.
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct Bubble {
    r#type: Option<String>,
    text: Option<String>,
    raw_text: Option<String>,
    timing_info: Option<TimingInfo>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct TimingInfo {
    start_time: Option<i64>,
}

/// One `aiService.prompts` history record: a prompt/response exchange.
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct Prompt {
    prompt: Option<String>,
    response: Option<String>,
    created_at: Option<i64>,
    conversation_id: Option<String>,
}

impl ProviderAdapter for CursorAdapter {
    fn provider_id(&self) -> &str {
        "cursor"
    }

    fn manifest(&self) -> AdapterManifest {
        manifest_for(
            self.provider_id(),
            Some(1),
            &[
                "SQLite source has no byte spans",
                "chatdata/prompts are multi-generation formats; version layering is not yet implemented",
                "native message ids are not preserved (synthetic cursor-msg-{seq})",
            ],
        )
    }

    fn probe(&self, bytes: &[u8]) -> Result<ProbeResult, ProviderError> {
        let mut matched = Vec::new();
        let unmatched = Vec::new();

        // Quick check: SQLite files start with a magic header.
        if bytes.len() < SQLITE_MAGIC.len() || &bytes[..SQLITE_MAGIC.len()] != SQLITE_MAGIC {
            return Err(ProviderError::AmbiguousVariant(
                "not a SQLite database (missing magic header)".into(),
            ));
        }
        matched.push("SQLite magic header detected".into());

        // Open read-only and check for the VS Code ItemTable KV table.
        let conn = open_readonly_from_bytes(bytes)
            .map_err(|e| ProviderError::StructuralFatal(format!("failed to open SQLite: {e}")))?;
        if !table_exists(&conn, "ItemTable") {
            return Err(ProviderError::AmbiguousVariant(
                "no `ItemTable` table found — not a Cursor state database".into(),
            ));
        }
        matched.push("ItemTable found".into());

        // Cursor chat history lives under either of two ItemTable keys.
        let has_chat_data = key_exists(&conn, CHAT_DATA_KEY);
        let has_prompts = key_exists(&conn, PROMPTS_KEY);
        if !has_chat_data && !has_prompts {
            return Err(ProviderError::AmbiguousVariant(
                "ItemTable has neither the Cursor chatdata nor prompts key".into(),
            ));
        }
        if has_chat_data {
            matched.push("Cursor chatdata key found".into());
        }
        if has_prompts {
            matched.push("Cursor prompts key found".into());
        }

        Ok(ProbeResult {
            variant_id: VARIANT_ID.to_string(),
            confidence: Confidence::Confirmed,
            matched_evidence: matched,
            unmatched_evidence: unmatched,
        })
    }

    fn parse(
        &self,
        bytes: &[u8],
        sink: &mut dyn CanonicalEventSink,
    ) -> Result<ParseReport, ProviderError> {
        let conn = open_readonly_from_bytes(bytes)
            .map_err(|e| ProviderError::StructuralFatal(format!("failed to open SQLite: {e}")))?;

        let mut report = ParseReport::default();
        let mut seq: u32 = 0;
        let mut session_count = 0usize;

        // Chat tabs first, then the flat prompts history (hstry order).
        match read_key(&conn, CHAT_DATA_KEY) {
            Ok(Some(value)) if !value.trim().is_empty() => {
                parse_chat_data(&value, sink, &mut report, &mut seq, &mut session_count)?;
            }
            Ok(_) => {}
            Err(e) => {
                report.skipped += 1;
                report
                    .diagnostics
                    .push(format!("failed to read chatdata value: {e}"));
            }
        }
        match read_key(&conn, PROMPTS_KEY) {
            Ok(Some(value)) if !value.trim().is_empty() => {
                parse_prompts(&value, sink, &mut report, &mut seq, &mut session_count)?;
            }
            Ok(_) => {}
            Err(e) => {
                report.skipped += 1;
                report
                    .diagnostics
                    .push(format!("failed to read prompts value: {e}"));
            }
        }

        // Fail closed for multi-session sources (ADR-0009): no single native id
        // may be claimed authoritative when the file holds several sessions.
        if session_count > 1 {
            report.session_observation.multi_session = true;
            report.session_observation.provider_session_id = MetadataResolution::Ambiguous;
            let suffix = report
                .session_native_id
                .as_deref()
                .map(|id| format!("，全部消息归属首个会话 {id}"))
                .unwrap_or_default();
            report.diagnostics.push(format!(
                "state.vscdb 包含 {session_count} 个不同会话——单文件=单会话{suffix}"
            ));
        }

        Ok(report)
    }
}

/// Parse the chatdata JSON document: each tab is one session, each bubble one
/// message ordered by `timingInfo.startTime` (tabs by `createdAt`).
fn parse_chat_data(
    value: &str,
    sink: &mut dyn CanonicalEventSink,
    report: &mut ParseReport,
    seq: &mut u32,
    session_count: &mut usize,
) -> Result<(), ProviderError> {
    let data: ChatData = match serde_json::from_str(value) {
        Ok(data) => data,
        Err(e) => {
            report.skipped += 1;
            report
                .diagnostics
                .push(format!("chatdata value is not valid JSON, skipped: {e}"));
            return Ok(());
        }
    };

    let mut tabs = data.tabs;
    // Sessions in chronological order of tab creation.
    tabs.sort_by_key(|tab| tab.created_at.unwrap_or(i64::MAX));

    for tab in tabs {
        // Keep bubbles with a type and non-empty text (text ?? rawText).
        let mut bubbles: Vec<(String, String, Option<i64>)> = Vec::new();
        for bubble in tab.bubbles {
            let Some(r#type) = bubble.r#type else {
                continue;
            };
            let text = bubble.text.or(bubble.raw_text).unwrap_or_default();
            if r#type.is_empty() || text.trim().is_empty() {
                continue;
            }
            let start = bubble.timing_info.as_ref().and_then(|t| t.start_time);
            let role = if r#type == "user" {
                "user"
            } else {
                "assistant"
            };
            bubbles.push((text, role.to_string(), start));
        }
        if bubbles.is_empty() {
            continue;
        }

        register_session(report, session_count, tab.id.as_deref());
        // Chronological order within the tab by bubble start time.
        bubbles.sort_by_key(|(_, _, start)| start.unwrap_or(i64::MAX));
        for (text, role, start) in bubbles {
            emit_message(
                sink,
                report,
                seq,
                &role,
                &text,
                start.map(|t| t.to_string()),
            )?;
        }
    }
    Ok(())
}

/// Parse the prompts JSON array: prompts grouped by conversationId, each
/// group one session, each prompt/response pair a user + assistant message.
fn parse_prompts(
    value: &str,
    sink: &mut dyn CanonicalEventSink,
    report: &mut ParseReport,
    seq: &mut u32,
    session_count: &mut usize,
) -> Result<(), ProviderError> {
    let prompts: Vec<Prompt> = match serde_json::from_str(value) {
        Ok(prompts) => prompts,
        Err(e) => {
            report.skipped += 1;
            report
                .diagnostics
                .push(format!("prompts value is not valid JSON, skipped: {e}"));
            return Ok(());
        }
    };

    // Group by conversationId as-is (real data stores "" when absent).
    let mut grouped: std::collections::BTreeMap<String, Vec<Prompt>> =
        std::collections::BTreeMap::new();
    for prompt in prompts {
        grouped
            .entry(prompt.conversation_id.clone().unwrap_or_default())
            .or_default()
            .push(prompt);
    }

    // Conversations in chronological order of their first prompt.
    let mut groups: Vec<(String, Vec<Prompt>)> = grouped.into_iter().collect();
    groups.sort_by_key(|(_, prompts)| {
        prompts
            .iter()
            .filter_map(|p| p.created_at)
            .min()
            .unwrap_or(i64::MAX)
    });

    for (conversation_id, mut prompts) in groups {
        // Chronological order within the conversation.
        prompts.sort_by_key(|p| p.created_at.unwrap_or(i64::MAX));

        let mut messages: Vec<(String, String, Option<i64>)> = Vec::new();
        for prompt in prompts {
            if let Some(text) = prompt.prompt.filter(|t| !t.trim().is_empty()) {
                messages.push(("user".to_string(), text, prompt.created_at));
            }
            if let Some(text) = prompt.response.filter(|t| !t.trim().is_empty()) {
                messages.push(("assistant".to_string(), text, prompt.created_at));
            }
        }
        if messages.is_empty() {
            continue;
        }

        let id = (!conversation_id.trim().is_empty()).then_some(conversation_id.as_str());
        register_session(report, session_count, id);
        for (role, text, created_at) in messages {
            emit_message(
                sink,
                report,
                seq,
                &role,
                &text,
                created_at.map(|t| t.to_string()),
            )?;
        }
    }
    Ok(())
}

/// Count one more session and, when it is the first with a native id, claim
/// it as the document session id (overridden to ambiguous at the end when
/// the document turns out to hold multiple sessions).
fn register_session(report: &mut ParseReport, session_count: &mut usize, native_id: Option<&str>) {
    *session_count += 1;
    let Some(id) = native_id.map(str::trim).filter(|s| !s.is_empty()) else {
        return;
    };
    if report.session_native_id.is_none() {
        report.session_native_id = Some(id.to_string());
        report.session_observation.provider_session_id =
            MetadataResolution::Resolved(id.to_string());
    }
}

/// Emit one canonical message with a document-stable synthetic native id.
///
/// Bubbles and prompt records carry no per-message id (a tab id or prompt id
/// is shared by several messages), so a sequence-derived id is used, same as
/// the cline/codebuddy/qoder adapters.
fn emit_message(
    sink: &mut dyn CanonicalEventSink,
    report: &mut ParseReport,
    seq: &mut u32,
    role: &str,
    text: &str,
    timestamp: Option<String>,
) -> Result<(), ProviderError> {
    sink.emit_message(MessageEvent {
        seq: *seq,
        native_id: &format!("cursor-msg-{}", *seq),
        parent_native_id: None,
        role,
        text,
        timestamp: timestamp.as_deref(),
        is_sidechain: false,
        span: None, // SQLite has no byte spans
    })
    .map_err(|e| ProviderError::StructuralFatal(e.to_string()))?;
    *seq += 1;
    report.committed += 1;
    Ok(())
}

/// Open a SQLite database from bytes, read-only.
///
/// Writes bytes to a temp file, opens with SQLITE_OPEN_READONLY + busy_timeout,
/// and returns the connection. The temp file is removed by the OS.
fn open_readonly_from_bytes(bytes: &[u8]) -> Result<Connection, String> {
    let temp_path = temp_db_path("parse");
    let mut file = std::fs::File::create(&temp_path).map_err(|e| e.to_string())?;
    file.write_all(bytes).map_err(|e| e.to_string())?;
    file.sync_all().map_err(|e| e.to_string())?;
    drop(file);

    let conn = Connection::open_with_flags(
        &temp_path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|e| e.to_string())?;
    conn.busy_timeout(std::time::Duration::from_secs(1))
        .map_err(|e| e.to_string())?;

    // Best-effort cleanup: the temp file is left for the OS.
    let _ = temp_path; // keep path alive for conn

    Ok(conn)
}

/// Unique temp file path for a purpose: process id + atomic counter prevent
/// concurrent parses (and parallel tests) from colliding on the same name.
fn temp_db_path(tag: &str) -> std::path::PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    std::env::temp_dir().join(format!(
        "asg-cursor-{}-{tag}.db",
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ))
}

/// Check if a table exists in the database.
fn table_exists(conn: &Connection, table_name: &str) -> bool {
    conn.prepare(&format!(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='{table_name}'"
    ))
    .and_then(|mut stmt| stmt.exists([]))
    .unwrap_or(false)
}

/// Check whether an ItemTable row with the given key exists.
fn key_exists(conn: &Connection, key: &str) -> bool {
    conn.prepare("SELECT key FROM ItemTable WHERE key = ?1")
        .and_then(|mut stmt| stmt.exists(params![key]))
        .unwrap_or(false)
}

/// Read an ItemTable value by key; `Ok(None)` when the key is absent.
fn read_key(conn: &Connection, key: &str) -> Result<Option<String>, String> {
    let mut stmt = conn
        .prepare("SELECT value FROM ItemTable WHERE key = ?1")
        .map_err(|e| e.to_string())?;
    let mut rows = stmt.query(params![key]).map_err(|e| e.to_string())?;
    match rows.next().map_err(|e| e.to_string())? {
        Some(row) => row.get(0).map(Some).map_err(|e| e.to_string()),
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_matches_provider_matrix() {
        let adapter = CursorAdapter::new();
        let manifest = adapter.manifest();
        assert_eq!(manifest.provider_id, adapter.provider_id());
        assert_eq!(manifest.supported_variants, vec![VARIANT_ID.to_string()]);
        assert_eq!(manifest.capabilities.provider_id, adapter.provider_id());
        assert_eq!(manifest.capabilities.variant_id, VARIANT_ID);
        assert!(manifest.last_certified_targets.is_empty());
        assert_eq!(manifest.fixture_revision, Some(1));
    }

    /// Records (seq, role, text, timestamp) of every emitted message.
    struct RecordingSink {
        events: Vec<(u32, String, String, Option<String>)>,
    }
    impl CanonicalEventSink for RecordingSink {
        fn emit_message(
            &mut self,
            event: MessageEvent<'_>,
        ) -> agent_session_grep_ports::PortResult<()> {
            self.events.push((
                event.seq,
                event.role.to_string(),
                event.text.to_string(),
                event.timestamp.map(str::to_string),
            ));
            Ok(())
        }
    }

    fn sink() -> RecordingSink {
        RecordingSink { events: Vec::new() }
    }

    /// Serialize an in-memory database to bytes via VACUUM INTO.
    fn vacuum_to_bytes(conn: &Connection) -> Vec<u8> {
        let temp_path = temp_db_path("test");
        conn.execute_batch(&format!("VACUUM INTO '{}'", temp_path.display()))
            .unwrap();
        let bytes = std::fs::read(&temp_path).unwrap();
        let _ = std::fs::remove_file(&temp_path);
        bytes
    }

    /// Build a synthetic Cursor `state.vscdb` (ItemTable + given key values).
    fn create_cursor_db(chatdata: Option<&str>, prompts: Option<&str>) -> Vec<u8> {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("CREATE TABLE ItemTable (key TEXT PRIMARY KEY, value TEXT);")
            .unwrap();
        if let Some(value) = chatdata {
            conn.execute(
                "INSERT INTO ItemTable (key, value) VALUES (?1, ?2)",
                params![CHAT_DATA_KEY, value],
            )
            .unwrap();
        }
        if let Some(value) = prompts {
            conn.execute(
                "INSERT INTO ItemTable (key, value) VALUES (?1, ?2)",
                params![PROMPTS_KEY, value],
            )
            .unwrap();
        }
        vacuum_to_bytes(&conn)
    }

    #[test]
    fn probe_rejects_non_sqlite_bytes() {
        let adapter = CursorAdapter::new();
        let err = adapter.probe(b"not a sqlite file").unwrap_err();
        assert!(matches!(err, ProviderError::AmbiguousVariant(_)));
    }

    #[test]
    fn probe_rejects_empty_sqlite_db() {
        let adapter = CursorAdapter::new();
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("CREATE TABLE unrelated (id INTEGER);")
            .unwrap();
        let db_bytes = vacuum_to_bytes(&conn);
        let err = adapter.probe(&db_bytes).unwrap_err();
        assert!(matches!(err, ProviderError::AmbiguousVariant(_)));
    }

    #[test]
    fn probe_rejects_itemtable_without_cursor_keys() {
        let adapter = CursorAdapter::new();
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE ItemTable (key TEXT PRIMARY KEY, value TEXT);
             INSERT INTO ItemTable VALUES ('some.other.key', 'x');",
        )
        .unwrap();
        let db_bytes = vacuum_to_bytes(&conn);
        let err = adapter.probe(&db_bytes).unwrap_err();
        assert!(matches!(err, ProviderError::AmbiguousVariant(_)));
    }

    #[test]
    fn probe_confirms_cursor_state_db() {
        let adapter = CursorAdapter::new();
        let db_bytes = create_cursor_db(Some(r#"{"tabs":[{"id":"tab-1","bubbles":[]}]}"#), None);
        let result = adapter.probe(&db_bytes).unwrap();
        assert_eq!(result.variant_id, VARIANT_ID);
        assert_eq!(result.confidence, Confidence::Confirmed);
        assert!(
            result
                .matched_evidence
                .iter()
                .any(|e| e.contains("chatdata"))
        );
    }

    #[test]
    fn probe_confirms_with_prompts_only() {
        let adapter = CursorAdapter::new();
        let db_bytes = create_cursor_db(None, Some(r#"[]"#));
        let result = adapter.probe(&db_bytes).unwrap();
        assert_eq!(result.confidence, Confidence::Confirmed);
        assert!(
            result
                .matched_evidence
                .iter()
                .any(|e| e.contains("prompts"))
        );
    }

    #[test]
    fn parse_extracts_chatdata_messages() {
        let adapter = CursorAdapter::new();
        let chatdata = r#"{"tabs":[{"id":"tab-1","title":"Test","createdAt":100,"lastUpdatedAt":200,
            "bubbles":[
              {"type":"user","text":"hello","rawText":"ignored","timingInfo":{"startTime":101}},
              {"type":"assistant","text":"hi there","rawText":"alt","timingInfo":{"startTime":102}}
            ]}]}"#;
        let db_bytes = create_cursor_db(Some(chatdata), None);
        let mut sink = sink();
        let report = adapter.parse(&db_bytes, &mut sink).unwrap();

        assert_eq!(report.committed, 2);
        assert_eq!(report.skipped, 0);
        assert_eq!(report.session_native_id.as_deref(), Some("tab-1"));
        assert_eq!(
            report.session_observation.provider_session_id,
            MetadataResolution::Resolved("tab-1".into())
        );
        assert!(!report.session_observation.multi_session);
        assert_eq!(sink.events.len(), 2);
        // user message, text wins over rawText.
        assert_eq!(sink.events[0].0, 0);
        assert_eq!(sink.events[0].1, "user");
        assert_eq!(sink.events[0].2, "hello");
        assert_eq!(sink.events[0].3.as_deref(), Some("101"));
        assert_eq!(sink.events[1].0, 1);
        assert_eq!(sink.events[1].1, "assistant");
        assert_eq!(sink.events[1].2, "hi there");
        assert_eq!(sink.events[1].3.as_deref(), Some("102"));
    }

    #[test]
    fn parse_filters_invalid_bubbles_and_orders_by_time() {
        let adapter = CursorAdapter::new();
        let chatdata = r#"{"tabs":[{"id":"tab-1","createdAt":1,
            "bubbles":[
              {"type":"assistant","text":"later","timingInfo":{"startTime":200}},
              {"type":"user","text":"first","timingInfo":{"startTime":100}},
              {"type":"user","rawText":"raw only","timingInfo":{"startTime":150}},
              {"type":"","text":"no type"},
              {"type":"assistant","text":"  "},
              {"type":"user","text":"no timing"}
            ]}]}"#;
        let db_bytes = create_cursor_db(Some(chatdata), None);
        let mut sink = sink();
        let report = adapter.parse(&db_bytes, &mut sink).unwrap();

        assert_eq!(report.committed, 4);
        // Ordered by startTime; the untimed bubble sorts last.
        assert_eq!(sink.events[0].2, "first");
        assert_eq!(sink.events[1].2, "raw only");
        assert_eq!(sink.events[2].2, "later");
        assert_eq!(sink.events[3].2, "no timing");
        assert_eq!(sink.events[3].3, None);
        assert_eq!(sink.events[0].1, "user");
        assert_eq!(sink.events[2].1, "assistant");
    }

    #[test]
    fn parse_groups_prompts_by_conversation_id() {
        let adapter = CursorAdapter::new();
        let prompts = r#"[{"id":"p1","prompt":"q1","response":"a1","createdAt":100,"conversationId":"conv-a"},
            {"id":"p2","prompt":"q2","response":"","createdAt":200,"conversationId":"conv-a"},
            {"id":"p3","prompt":"","response":"a3","createdAt":300,"conversationId":"conv-b"}]"#;
        let db_bytes = create_cursor_db(None, Some(prompts));
        let mut sink = sink();
        let report = adapter.parse(&db_bytes, &mut sink).unwrap();

        // conv-a: user q1, assistant a1, user q2; conv-b: assistant a3.
        assert_eq!(report.committed, 4);
        assert_eq!(report.session_native_id.as_deref(), Some("conv-a"));
        assert!(report.session_observation.multi_session);
        assert_eq!(
            report.session_observation.provider_session_id,
            MetadataResolution::Ambiguous
        );
        assert!(
            report
                .diagnostics
                .iter()
                .any(|d| d.contains("2 个不同会话"))
        );
        // conv-a (earliest 100) emits before conv-b (300).
        let roles: Vec<&str> = sink.events.iter().map(|e| e.1.as_str()).collect();
        assert_eq!(roles, ["user", "assistant", "user", "assistant"]);
        assert_eq!(
            sink.events.iter().map(|e| e.2.as_str()).collect::<Vec<_>>(),
            ["q1", "a1", "q2", "a3"]
        );
        assert_eq!(sink.events[1].3.as_deref(), Some("100"));
        assert_eq!(sink.events[3].3.as_deref(), Some("300"));
    }

    #[test]
    fn parse_single_prompt_conversation_resolves_session_id() {
        let adapter = CursorAdapter::new();
        let prompts = r#"[{"id":"p1","prompt":"q1","response":"a1","createdAt":100,"conversationId":"only-conv"}]"#;
        let db_bytes = create_cursor_db(None, Some(prompts));
        let mut sink = sink();
        let report = adapter.parse(&db_bytes, &mut sink).unwrap();

        assert_eq!(report.committed, 2);
        assert_eq!(report.session_native_id.as_deref(), Some("only-conv"));
        assert_eq!(
            report.session_observation.provider_session_id,
            MetadataResolution::Resolved("only-conv".into())
        );
        assert!(!report.session_observation.multi_session);
    }

    #[test]
    fn parse_missing_native_ids_leave_session_claims_missing() {
        let adapter = CursorAdapter::new();
        // Tab without id + prompts with empty conversationId: two sessions,
        // neither carrying a native id.
        let chatdata =
            r#"{"tabs":[{"bubbles":[{"type":"user","text":"hi","timingInfo":{"startTime":1}}]}]}"#;
        let prompts =
            r#"[{"id":"p1","prompt":"q","response":"a","createdAt":2,"conversationId":""}]"#;
        let db_bytes = create_cursor_db(Some(chatdata), Some(prompts));
        let mut sink = sink();
        let report = adapter.parse(&db_bytes, &mut sink).unwrap();

        assert_eq!(report.committed, 3);
        assert_eq!(report.session_native_id, None);
        // Multi-session fail-closes to ambiguous even without any native id.
        assert_eq!(
            report.session_observation.provider_session_id,
            MetadataResolution::Ambiguous
        );
        assert!(report.session_observation.multi_session);
    }
}
