//! Runtime-generated synthetic logical SQLite images; no real history/config.
use std::io::{BufRead, Cursor};
use std::time::{Duration, Instant};

use agent_session_grep_domain::{
    ToolActivity, ToolActivityActor, ToolActivityKind, ToolActivityStatus,
};
use agent_session_grep_ports::{
    CanonicalEventSink, Confidence, MessageEvent, MetadataResolution, PortError, PortResult,
    ProviderAdapter, ProviderError, ProviderSessionIdentity, ReadOnlySource,
    SQLITE_MAX_SOURCE_BYTES, STREAM_RECORD_MAX_BYTES, SliceSource, StreamingSupport,
    ToolActivityEvent,
};
use agent_session_grep_provider_zcode::{
    MAX_DECODED_BYTES, MAX_SQLITE_BYTES, PartData, Presence, SnapshotError, ZCodeAdapter,
    inspect_snapshot,
};
use rusqlite::{Connection, MAIN_DB, params};
use serde_json::{Value, json};

const SCHEMA: &str = "PRAGMA foreign_keys=ON;
CREATE TABLE session(id TEXT PRIMARY KEY,project_id TEXT,parent_id TEXT,directory TEXT,version TEXT,time_created INTEGER,time_updated INTEGER,revert TEXT);
CREATE TABLE message(id TEXT PRIMARY KEY,session_id TEXT NOT NULL REFERENCES session(id) ON DELETE CASCADE,time_created INTEGER,time_updated INTEGER,data TEXT,sequence INTEGER);
CREATE TABLE part(id TEXT PRIMARY KEY,message_id TEXT NOT NULL REFERENCES message(id) ON DELETE CASCADE,session_id TEXT NOT NULL REFERENCES session(id) ON DELETE CASCADE,time_created INTEGER,time_updated INTEGER,data TEXT,sequence INTEGER);
CREATE TABLE session_entry(id TEXT PRIMARY KEY,session_id TEXT,kind TEXT,data TEXT);";
fn end() -> Instant {
    Instant::now() + Duration::from_secs(5)
}
fn database() -> Connection {
    let db = Connection::open_in_memory().unwrap();
    db.execute_batch(SCHEMA).unwrap();
    db
}
fn image(db: &Connection) -> Vec<u8> {
    db.serialize(MAIN_DB).unwrap().to_vec()
}
fn session(db: &Connection, id: &str, parent: Option<&str>) {
    db.execute("INSERT INTO session VALUES(?1,'synthetic-project',?2,'/synthetic/project','0.16.9',1000,2000,NULL)", params![id,parent]).unwrap();
}
fn message(db: &Connection, id: &str, session: &str, sequence: i64, role: &str, created: i64) {
    db.execute(
        "INSERT INTO message VALUES(?1,?2,?3,?3,?4,?5)",
        params![
            id,
            session,
            created,
            json!({"role":role,"unknownAdditive":{"ignored":true}}).to_string(),
            sequence
        ],
    )
    .unwrap();
}
fn part(db: &Connection, id: &str, message: &str, session: &str, sequence: i64, data: Value) {
    db.execute(
        "INSERT INTO part VALUES(?1,?2,?3,9000,9001,?4,?5)",
        params![id, message, session, data.to_string(), sequence],
    )
    .unwrap();
}
#[derive(Debug)]
struct Captured {
    session: ProviderSessionIdentity,
    native_id: String,
    parent: Option<String>,
    text: String,
    role: String,
    seq: u32,
    timestamp: Option<String>,
    sidechain: bool,
    span: Option<(u64, u64)>,
}
#[derive(Default)]
struct Sink {
    messages: Vec<Captured>,
    activities: Vec<(String, ToolActivity)>,
}
impl CanonicalEventSink for Sink {
    fn emit_message(&mut self, event: MessageEvent<'_>) -> PortResult<()> {
        self.messages.push(Captured {
            session: event.session.unwrap().clone(),
            native_id: event.native_id.into(),
            parent: event.parent_native_id.map(str::to_string),
            text: event.text.into(),
            role: event.role.into(),
            seq: event.seq,
            timestamp: event.timestamp.map(str::to_string),
            sidechain: event.is_sidechain,
            span: event.span,
        });
        Ok(())
    }
    fn emit_activity(&mut self, event: ToolActivityEvent<'_>) -> PortResult<()> {
        self.activities
            .push((event.message_native_id.into(), event.activity));
        Ok(())
    }
}
#[test]
fn sequence_native_identity_epoch_and_parent_child_membership_are_exact() {
    let db = database();
    session(&db, "parent", None);
    session(&db, "child", Some("parent"));
    session(&db, "empty-session", None);
    message(&db, "later", "parent", 20, "assistant", 1);
    message(&db, "earlier", "parent", 10, "user", 1_700_000_000_123);
    message(&db, "child-message", "child", 3, "assistant", 2);
    part(
        &db,
        "p-late-b",
        "later",
        "parent",
        8,
        json!({"type":"text","text":"second"}),
    );
    part(
        &db,
        "p-late-a",
        "later",
        "parent",
        4,
        json!({"type":"text","text":" first 中文 "}),
    );
    part(
        &db,
        "p-first",
        "earlier",
        "parent",
        0,
        json!({"type":"text","text":"original"}),
    );
    part(
        &db,
        "p-child",
        "child-message",
        "child",
        1,
        json!({"type":"text","text":"independent child"}),
    );
    let bytes = image(&db);
    let before = bytes.clone();
    let graph = inspect_snapshot(&bytes, end()).unwrap();
    assert!(graph.is_complete());
    assert_eq!(graph.sessions().len(), 3);
    assert_eq!(
        graph
            .sessions()
            .iter()
            .find(|s| s.native_id == "child")
            .unwrap()
            .parent_native_id
            .as_deref(),
        Some("parent")
    );
    assert_eq!(
        graph.sessions()[0].project_id.as_deref(),
        Some("synthetic-project")
    );
    let later = graph
        .messages()
        .iter()
        .find(|m| m.native_id == "later")
        .unwrap();
    assert_eq!(later.sequence, 20);
    assert_eq!(later.parts[0].native_id, "p-late-a");
    assert_eq!(later.parts[1].native_id, "p-late-b");
    let mut sink = Sink::default();
    let report = ZCodeAdapter::new().parse(&bytes, &mut sink).unwrap();
    assert_eq!(report.committed, 3);
    assert_eq!(report.skipped, 0);
    assert!(report.session_native_id.is_none());
    assert!(report.session_observation.multi_session);
    assert_eq!(
        report.session_observation.provider_session_id,
        MetadataResolution::Ambiguous
    );
    assert_eq!(
        sink.messages
            .iter()
            .map(|m| m.native_id.as_str())
            .collect::<Vec<_>>(),
        vec!["zcode:child-message", "zcode:earlier", "zcode:later"]
    );
    assert_eq!(
        sink.messages.iter().map(|m| m.seq).collect::<Vec<_>>(),
        vec![0, 1, 2]
    );
    assert_eq!(sink.messages[2].text, " first 中文 \nsecond");
    assert_eq!(
        sink.messages[1].timestamp.as_deref(),
        Some("2023-11-14T22:13:20.123Z")
    );
    assert_eq!(sink.messages[1].role, "user");
    assert_eq!(sink.messages[0].session.source_key, "child");
    assert!(sink.messages[0].sidechain);
    assert_eq!(sink.messages[1].session.source_key, "parent");
    assert!(!sink.messages[1].sidechain);
    assert!(
        sink.messages
            .iter()
            .all(|m| m.parent.is_none() && m.span.is_none())
    );
    assert_eq!(bytes, before);
}
#[test]
fn text_reasoning_tool_and_file_stay_separate_and_tool_only_messages_have_anchors() {
    let db = database();
    session(&db, "child", Some("missing-parent"));
    message(&db, "with-text", "child", 1, "assistant", 0);
    message(&db, "tool-only", "child", 2, "assistant", 1);
    for (id, sequence, data) in [
        ("text", 1, json!({"type":"text","text":"visible"})),
        (
            "reason",
            2,
            json!({"type":"reasoning","text":"private reasoning body","metadata":{"signature":"synthetic"}}),
        ),
        (
            "tool",
            3,
            json!({"type":"tool","callID":"native-call","tool":"shell","state":{"status":"completed","input":{"command":"synthetic command"},"output":"private tool output"}}),
        ),
        (
            "file",
            4,
            json!({"type":"file","filename":"synthetic.txt","mime":"text/plain","url":"file:synthetic"}),
        ),
        ("start", 5, json!({"type":"step-start"})),
        (
            "finish",
            6,
            json!({"type":"step-finish","cost":0,"tokens":{"input":7}}),
        ),
        (
            "timeline",
            7,
            json!({"type":"timeline","display":"not prose"}),
        ),
        ("compact", 8, json!({"type":"compaction"})),
    ] {
        part(&db, id, "with-text", "child", sequence, data);
    }
    part(
        &db,
        "only-tool",
        "tool-only",
        "child",
        1,
        json!({"type":"tool","callID":"other-call","tool":"unknown-plugin","state":{"status":"running","input":{"command":"must not infer"},"error":"private error"}}),
    );
    let bytes = image(&db);
    let graph = inspect_snapshot(&bytes, end()).unwrap();
    assert!(
        matches!(&graph.messages()[0].parts[1].data,PartData::Reasoning{text} if text=="private reasoning body")
    );
    assert!(
        matches!(&graph.messages()[0].parts[2].data,PartData::Tool{call_id,..} if call_id=="native-call")
    );
    let mut sink = Sink::default();
    let report = ZCodeAdapter::new().parse(&bytes, &mut sink).unwrap();
    assert_eq!(report.committed, 2);
    assert_eq!(report.skipped, 0);
    assert_eq!(sink.messages[0].text, "visible");
    assert_eq!(sink.messages[1].text, "");
    assert_eq!(sink.activities.len(), 4);
    assert!(
        sink.activities
            .iter()
            .all(|(_, a)| a.actor == ToolActivityActor::Subagent)
    );
    let (_, tool) = sink
        .activities
        .iter()
        .find(|(_, a)| a.name == "shell")
        .unwrap();
    assert_eq!(tool.kind, ToolActivityKind::Command);
    assert_eq!(tool.status, ToolActivityStatus::Success);
    assert_eq!(tool.target.as_deref(), Some("synthetic command"));
    let (anchor, tool) = sink
        .activities
        .iter()
        .find(|(_, a)| a.name == "unknown-plugin")
        .unwrap();
    assert_eq!(anchor, "zcode:tool-only");
    assert_eq!(tool.status, ToolActivityStatus::Unknown);
    assert_eq!(tool.kind, ToolActivityKind::Unknown);
    assert!(tool.target.is_none());
    assert!(!format!("{graph:?}").contains("private"));
}
#[test]
fn tool_input_large_nested_metadata_is_raw_and_shared_target_rules_remain_exact() {
    let db = database();
    session(&db, "s", None);
    message(&db, "m", "s", 0, "assistant", 0);
    part(
        &db,
        "p",
        "m",
        "s",
        0,
        json!({"type":"tool","callID":"c","tool":"shell","state":{
        "status":"error", "input":{"path":42,"command":"  synthetic exact command  ","unused":vec![0;100_000]},
        "error":"private tool error", "output":["private output"]}}),
    );
    let bytes = image(&db);
    let graph = inspect_snapshot(&bytes, end()).unwrap();
    assert!(graph.is_complete());
    let mut sink = Sink::default();
    ZCodeAdapter::new().parse(&bytes, &mut sink).unwrap();
    assert_eq!(sink.activities.len(), 1);
    assert_eq!(sink.activities[0].1.status, ToolActivityStatus::Error);
    assert_eq!(
        sink.activities[0].1.target.as_deref(),
        Some("synthetic exact command")
    );
    assert_eq!(sink.messages[0].text, "");
}
#[test]
fn version_is_opaque_schema_is_positive_and_other_sqlite_formats_are_rejected() {
    let db = database();
    session(&db, "s", None);
    message(&db, "m", "s", 0, "user", 0);
    db.execute_batch("PRAGMA user_version=9001; UPDATE session SET version='future.opaque.value'")
        .unwrap();
    let graph = inspect_snapshot(&image(&db), end()).unwrap();
    assert!(graph.is_complete());
    assert_eq!(
        graph.sessions()[0].version.as_deref(),
        Some("future.opaque.value")
    );
    let adapter = ZCodeAdapter::new();
    let probe = adapter.probe(&image(&db)).unwrap();
    assert_eq!(adapter.provider_id(), "zcode");
    assert_eq!(probe.variant_id, "zcode/sqlite-v1");
    assert_eq!(probe.confidence, Confidence::Confirmed);
    db.execute_batch("DROP TABLE session_entry").unwrap();
    assert_eq!(
        inspect_snapshot(&image(&db), end()).unwrap_err(),
        SnapshotError::UnsupportedSchema
    );
    assert!(matches!(
        adapter.probe(&image(&db)),
        Err(ProviderError::AmbiguousVariant(_))
    ));
    let other = Connection::open_in_memory().unwrap();
    other.execute_batch("CREATE TABLE sessions(id TEXT,deleted_at); CREATE TABLE session(id TEXT); CREATE TABLE message(id TEXT); CREATE TABLE part(id TEXT)").unwrap();
    assert!(matches!(
        adapter.probe(&image(&other)),
        Err(ProviderError::AmbiguousVariant(_))
    ));
    assert!(matches!(
        adapter.probe(b"{\"type\":\"message\"}"),
        Err(ProviderError::AmbiguousVariant(_))
    ));
}
#[test]
fn missing_generated_view_or_virtual_required_columns_do_not_masquerade_as_schema() {
    for replacement in [
        "DROP TABLE part; CREATE VIEW part AS SELECT 'p' AS id,'m' AS message_id,'s' AS session_id,'{}' AS data,1 AS sequence,0 AS time_created,0 AS time_updated;",
        "DROP TABLE part; CREATE TABLE part(id TEXT,message_id TEXT,session_id TEXT,data TEXT,time_created INTEGER,time_updated INTEGER);",
        "DROP TABLE part; CREATE TABLE part(id TEXT,message_id TEXT,session_id TEXT,data TEXT,time_created INTEGER,time_updated INTEGER,sequence INTEGER GENERATED ALWAYS AS (1));",
        "DROP TABLE session_entry; CREATE VIRTUAL TABLE session_entry USING fts5(text);",
    ] {
        let db = database();
        db.execute_batch(replacement).unwrap();
        assert_eq!(
            inspect_snapshot(&image(&db), end()).unwrap_err(),
            SnapshotError::UnsupportedSchema
        );
    }
}
#[test]
fn malformed_or_unknown_content_defers_whole_message_and_all_absence() {
    for invalid in [
        json!({"type":"future-kind","text":"do not publish"}),
        json!({"type":"text","text":42}),
        json!({"type":"reasoning","text":null}),
    ] {
        let db = database();
        session(&db, "s", None);
        message(&db, "good", "s", 0, "user", 0);
        message(&db, "bad", "s", 1, "assistant", 1);
        part(
            &db,
            "good-text",
            "good",
            "s",
            0,
            json!({"type":"text","text":"keep good"}),
        );
        part(
            &db,
            "valid-piece",
            "bad",
            "s",
            0,
            json!({"type":"text","text":"do not publish partial"}),
        );
        part(&db, "invalid-piece", "bad", "s", 1, invalid);
        let bytes = image(&db);
        let graph = inspect_snapshot(&bytes, end()).unwrap();
        assert!(!graph.is_complete());
        assert_eq!(graph.skipped_messages(), 1);
        assert_eq!(graph.session_presence("missing"), Presence::Unknown);
        assert_eq!(graph.message_presence("missing"), Presence::Unknown);
        assert_eq!(graph.part_presence("missing"), Presence::Unknown);
        assert_eq!(graph.message_presence("bad"), Presence::Present);
        assert_eq!(graph.part_presence("invalid-piece"), Presence::Present);
        let mut sink = Sink::default();
        let report = ZCodeAdapter::new().parse(&bytes, &mut sink).unwrap();
        assert_eq!(report.committed, 1);
        assert_eq!(report.skipped, 1);
        assert_eq!(sink.messages[0].text, "keep good");
        assert!(report.diagnostics.len() <= 32);
        assert!(!report.diagnostics.join(" ").contains("do not publish"));
    }
    let db = database();
    session(&db, "s", None);
    message(&db, "unknown-role", "s", 0, "system", 0);
    assert!(!inspect_snapshot(&image(&db), end()).unwrap().is_complete());
    db.execute("UPDATE message SET data='{broken synthetic JSON'", [])
        .unwrap();
    assert!(!inspect_snapshot(&image(&db), end()).unwrap().is_complete());
}
#[test]
fn cascade_hard_delete_is_proven_only_by_complete_current_scan_and_revert_rederives_rows() {
    let db = database();
    session(&db, "s", None);
    message(&db, "m", "s", 0, "user", 0);
    part(
        &db,
        "p",
        "m",
        "s",
        0,
        json!({"type":"text","text":"original"}),
    );
    let initial = image(&db);
    let before = inspect_snapshot(&initial, end()).unwrap();
    assert_eq!(before.message_presence("m"), Presence::Present);
    db.execute(
        "UPDATE session SET revert=?1",
        [json!({"opaqueRewrite":true}).to_string()],
    )
    .unwrap();
    db.execute(
        "UPDATE part SET data=?1",
        [json!({"type":"text","text":"rewritten"}).to_string()],
    )
    .unwrap();
    let graph = inspect_snapshot(&image(&db), end()).unwrap();
    assert!(graph.sessions()[0].has_revert);
    assert!(matches!(&graph.messages()[0].parts[0].data,PartData::Text{text} if text=="rewritten"));
    db.execute("DELETE FROM session WHERE id='s'", []).unwrap();
    let after = inspect_snapshot(&image(&db), end()).unwrap();
    assert!(after.is_complete());
    assert!(after.messages().is_empty());
    assert_eq!(after.session_presence("s"), Presence::ConfirmedAbsent);
    assert_eq!(after.message_presence("m"), Presence::ConfirmedAbsent);
    assert_eq!(after.part_presence("p"), Presence::ConfirmedAbsent);
    assert_eq!(before.message_presence("m"), Presence::Present);
    assert_eq!(
        after.session_presence("invalid identity"),
        Presence::Unknown
    );
    assert_eq!(
        inspect_snapshot(&[], end()).unwrap_err(),
        SnapshotError::InvalidImage
    );
}
#[test]
fn graph_corruption_or_inexact_identity_cannot_emit_staging_or_confirm_absence() {
    for mutation in [
        "PRAGMA foreign_keys=OFF; UPDATE message SET session_id='missing'",
        "UPDATE part SET session_id='other'",
        "UPDATE message SET sequence=NULL",
        "UPDATE part SET sequence=-1",
        "UPDATE message SET id=' padded ' WHERE id='m'",
        "UPDATE session SET parent_id='s'",
        "UPDATE message SET time_created='not-an-integer'",
    ] {
        let db = database();
        session(&db, "s", None);
        session(&db, "other", None);
        message(&db, "m", "s", 0, "user", 0);
        part(
            &db,
            "p",
            "m",
            "s",
            0,
            json!({"type":"text","text":"synthetic"}),
        );
        db.execute_batch("PRAGMA foreign_keys=OFF").unwrap();
        db.execute_batch(mutation).unwrap();
        let mut sink = Sink::default();
        assert!(ZCodeAdapter::new().parse(&image(&db), &mut sink).is_err());
        assert!(sink.messages.is_empty());
    }
    let db = database();
    session(&db, "a", Some("b"));
    session(&db, "b", Some("a"));
    assert_eq!(
        inspect_snapshot(&image(&db), end()).unwrap_err(),
        SnapshotError::InvalidGraph
    );
}
#[test]
fn ambiguous_sequences_and_duplicate_binary_ids_fail_instead_of_silent_overwrite() {
    for mutation in [
        "INSERT INTO message VALUES('another','s',1,1,'{\"role\":\"user\"}',0)",
        "INSERT INTO part VALUES('another','m','s',1,1,'{\"type\":\"text\",\"text\":\"new\"}',0)",
    ] {
        let db = database();
        session(&db, "s", None);
        message(&db, "m", "s", 0, "user", 0);
        part(
            &db,
            "p",
            "m",
            "s",
            0,
            json!({"type":"text","text":"synthetic"}),
        );
        db.execute_batch(mutation).unwrap();
        assert_eq!(
            inspect_snapshot(&image(&db), end()).unwrap_err(),
            SnapshotError::InvalidGraph
        );
    }
    let db = database();
    db.execute_batch("PRAGMA foreign_keys=OFF; DROP TABLE message; CREATE TABLE message(id TEXT,session_id TEXT,time_created INTEGER,time_updated INTEGER,data TEXT,sequence INTEGER)").unwrap();
    session(&db, "s", None);
    message(&db, "duplicate", "s", 0, "user", 0);
    message(&db, "duplicate", "s", 1, "user", 0);
    assert_eq!(
        inspect_snapshot(&image(&db), end()).unwrap_err(),
        SnapshotError::InvalidGraph
    );
}
#[test]
fn binary_native_ids_are_not_coerced_by_column_collation_and_namespaces_are_injective() {
    let db = database();
    session(&db, "s", None);
    for (index, id) in ["Message-A", "message-a", "中文", "zcode:中文"]
        .iter()
        .enumerate()
    {
        message(&db, id, "s", index as i64, "user", 0);
        part(
            &db,
            &format!("p{index}"),
            id,
            "s",
            0,
            json!({"type":"text","text":"synthetic"}),
        );
    }
    let graph = inspect_snapshot(&image(&db), end()).unwrap();
    let keys = graph
        .messages()
        .iter()
        .map(|m| m.message_key.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(keys.len(), 4);
    assert_eq!(
        graph.message_presence("MESSAGE-A"),
        Presence::ConfirmedAbsent
    );
    assert_eq!(graph.message_presence("Message-A"), Presence::Present);
}
#[test]
fn exact_milliseconds_are_projected_to_utc_and_absent_timestamp_stays_absent() {
    let db = database();
    session(&db, "s", None);
    for (index, (ms, expected)) in [
        (0, "1970-01-01T00:00:00.000Z"),
        (951_782_400_123, "2000-02-29T00:00:00.123Z"),
        (253_402_300_799_999, "9999-12-31T23:59:59.999Z"),
    ]
    .iter()
    .enumerate()
    {
        message(&db, &format!("m{index}"), "s", index as i64, "user", *ms);
        let mut sink = Sink::default();
        ZCodeAdapter::new().parse(&image(&db), &mut sink).unwrap();
        assert_eq!(sink.messages[index].timestamp.as_deref(), Some(*expected));
    }
    db.execute("UPDATE message SET time_created=NULL", [])
        .unwrap();
    let mut sink = Sink::default();
    ZCodeAdapter::new().parse(&image(&db), &mut sink).unwrap();
    assert!(sink.messages.iter().all(|m| m.timestamp.is_none()));
    db.execute("UPDATE message SET time_created=-1", [])
        .unwrap();
    assert_eq!(
        inspect_snapshot(&image(&db), end()).unwrap_err(),
        SnapshotError::InvalidRecord
    );
}
#[test]
fn image_header_limits_deadline_and_readonly_owned_memory_fail_closed() {
    let db = database();
    let original = image(&db);
    for (offset, value) in [(18, 0), (19, 3), (47, 5), (59, 4)] {
        let mut bytes = original.clone();
        bytes[offset] = value;
        assert_eq!(
            inspect_snapshot(&bytes, end()).unwrap_err(),
            SnapshotError::UnsupportedFormat
        );
    }
    let mut bytes = original.clone();
    bytes.pop();
    assert_eq!(
        inspect_snapshot(&bytes, end()).unwrap_err(),
        SnapshotError::InvalidImage
    );
    assert_eq!(
        inspect_snapshot(&original, Instant::now()).unwrap_err(),
        SnapshotError::DeadlineExceeded
    );
    let mut clone = Connection::open_in_memory().unwrap();
    clone
        .deserialize_read_exact(MAIN_DB, original.as_slice(), original.len(), true)
        .unwrap();
    assert!(clone.execute("DELETE FROM session", []).is_err());
    assert_eq!(image(&db), original);
}
struct Oversize;
impl ReadOnlySource for Oversize {
    fn len(&self) -> u64 {
        MAX_SQLITE_BYTES + 1
    }
    fn open(&self) -> PortResult<Box<dyn BufRead + Send>> {
        panic!("oversized source must be rejected before read")
    }
}
struct FailedRead;
impl ReadOnlySource for FailedRead {
    fn len(&self) -> u64 {
        100
    }
    fn open(&self) -> PortResult<Box<dyn BufRead + Send>> {
        Err(PortError::Backend("synthetic private backend".into()))
    }
}
struct ShortRead(Vec<u8>);
impl ReadOnlySource for ShortRead {
    fn len(&self) -> u64 {
        self.0.len() as u64 + 4096
    }
    fn open(&self) -> PortResult<Box<dyn BufRead + Send>> {
        Ok(Box::new(Cursor::new(self.0.clone())))
    }
}
#[test]
fn short_whole_image_read_cannot_turn_into_a_complete_absence_proof() {
    let db = database();
    let bytes = image(&db);
    assert!(inspect_snapshot(&bytes, end()).unwrap().is_complete());
    let mut sink = Sink::default();
    assert!(matches!(
        ZCodeAdapter::new().parse_source(&ShortRead(bytes), &mut sink),
        Err(ProviderError::StructuralFatal(_))
    ));
    assert!(sink.messages.is_empty());
}
#[test]
fn zcode_whole_image_manifest_has_explicit_256_mib_limit_without_widening_other_sqlite_sources() {
    assert_eq!(MAX_SQLITE_BYTES, 256 * 1024 * 1024);
    assert_eq!(SQLITE_MAX_SOURCE_BYTES, 128 * 1024 * 1024);
    assert_eq!(MAX_DECODED_BYTES, 128 * 1024 * 1024);
    let manifest = ZCodeAdapter::new().manifest();
    assert_eq!(
        manifest.streaming_support,
        StreamingSupport::BoundedWholeSource
    );
    assert_eq!(manifest.max_source_size, Some(MAX_SQLITE_BYTES));
    assert_eq!(manifest.max_record_size, None);
}
#[test]
fn above_legacy_size_within_zcode_bound_still_requires_a_full_supported_image() {
    struct DeclaredLegacyPlusOne;
    impl ReadOnlySource for DeclaredLegacyPlusOne {
        fn len(&self) -> u64 {
            SQLITE_MAX_SOURCE_BYTES + 1
        }
        fn open(&self) -> PortResult<Box<dyn BufRead + Send + '_>> {
            Err(PortError::SourceIo("synthetic incomplete image".into()))
        }
    }
    let mut sink = Sink::default();
    assert!(matches!(
        ZCodeAdapter::new().parse_source(&DeclaredLegacyPlusOne, &mut sink),
        Err(ProviderError::StructuralFatal(_))
    ));
    assert!(sink.messages.is_empty());
}
#[test]
fn source_api_checks_full_declared_size_before_open_and_scrubs_storage_failure() {
    let adapter = ZCodeAdapter::new();
    let mut sink = Sink::default();
    assert!(
        matches!(adapter.parse_source(&Oversize,&mut sink),Err(ProviderError::SourceTooLarge{actual,max}) if actual==MAX_SQLITE_BYTES+1&&max==MAX_SQLITE_BYTES)
    );
    let error = adapter.parse_source(&FailedRead, &mut sink).unwrap_err();
    assert!(!error.to_string().contains("private backend"));
    assert!(sink.messages.is_empty());
    let db = database();
    session(&db, "s", None);
    message(&db, "m", "s", 0, "user", 0);
    let bytes = image(&db);
    let report = adapter
        .parse_source(&SliceSource::new(&bytes), &mut sink)
        .unwrap();
    assert_eq!(report.committed, 1);
}
#[test]
fn oversized_part_and_joined_message_never_return_a_complete_truncated_scan() {
    let db = database();
    session(&db, "s", None);
    message(&db, "m", "s", 0, "user", 0);
    part(
        &db,
        "oversize",
        "m",
        "s",
        0,
        json!({"type":"text","text":"x".repeat(STREAM_RECORD_MAX_BYTES as usize)}),
    );
    assert!(matches!(
        inspect_snapshot(&image(&db), end()),
        Err(SnapshotError::RecordTooLarge { .. })
    ));
    let db = database();
    session(&db, "s", None);
    message(&db, "m", "s", 0, "user", 0);
    for index in 0..3 {
        part(
            &db,
            &format!("p{index}"),
            "m",
            "s",
            index,
            json!({"type":"text","text":"x".repeat((STREAM_RECORD_MAX_BYTES/3) as usize + 1)}),
        );
    }
    assert!(matches!(
        inspect_snapshot(&image(&db), end()),
        Err(SnapshotError::RecordTooLarge { .. })
    ));
}
struct RejectedSink;
impl CanonicalEventSink for RejectedSink {
    fn emit_message(&mut self, _: MessageEvent<'_>) -> PortResult<()> {
        Err(PortError::Backend("private sink details".into()))
    }
}
struct DelayedSink {
    messages: usize,
    original_end: Instant,
}
impl CanonicalEventSink for DelayedSink {
    fn emit_message(&mut self, _: MessageEvent<'_>) -> PortResult<()> {
        self.messages += 1;
        // A finite synthetic sink stalls once beyond the same caller budget.
        std::thread::sleep(
            self.original_end.saturating_duration_since(Instant::now()) + Duration::from_millis(2),
        );
        Ok(())
    }
}
#[test]
fn sink_delay_uses_original_deadline_and_never_emits_the_next_message() {
    let db = database();
    session(&db, "s", None);
    message(&db, "first", "s", 0, "user", 0);
    message(&db, "second", "s", 1, "user", 1);
    let original_end = Instant::now() + Duration::from_millis(500);
    let mut sink = DelayedSink {
        messages: 0,
        original_end,
    };
    assert!(matches!(
        ZCodeAdapter::new().parse_with_deadline(&image(&db), &mut sink, original_end),
        Err(ProviderError::StructuralFatal(_))
    ));
    assert_eq!(sink.messages, 1);
}
#[test]
fn sink_failures_are_private_and_do_not_become_success_reports() {
    let db = database();
    session(&db, "s", None);
    message(&db, "m", "s", 0, "user", 0);
    let error = ZCodeAdapter::new()
        .parse(&image(&db), &mut RejectedSink)
        .unwrap_err();
    assert!(!error.to_string().contains("private sink details"));
    assert!(matches!(error, ProviderError::StructuralFatal(_)));
}
#[test]
fn synthetic_wal_committed_rows_are_in_logical_backup_without_source_content_changes() {
    let temp = tempfile::tempdir().unwrap();
    let source = temp.path().join("synthetic.db");
    let db = Connection::open(&source).unwrap();
    db.execute_batch("PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0")
        .unwrap();
    db.execute_batch(SCHEMA).unwrap();
    session(&db, "s", None);
    message(&db, "m", "s", 0, "user", 0);
    part(
        &db,
        "p",
        "m",
        "s",
        0,
        json!({"type":"text","text":"committed WAL row"}),
    );
    let wal = std::path::PathBuf::from(format!("{}-wal", source.display()));
    let before_main = std::fs::read(&source).unwrap();
    let before_wal = std::fs::read(&wal).unwrap();
    assert!(before_wal.len() > 32);
    let mut logical = Connection::open_in_memory().unwrap();
    let backup = rusqlite::backup::Backup::new(&db, &mut logical).unwrap();
    backup.run_to_completion(8, Duration::ZERO, None).unwrap();
    drop(backup);
    let bytes = image(&logical);
    assert_eq!(bytes[18], 2);
    assert_eq!(bytes[19], 2);
    let before_bytes = bytes.clone();
    let mut sink = Sink::default();
    let report = ZCodeAdapter::new().parse(&bytes, &mut sink).unwrap();
    assert_eq!(report.committed, 1);
    assert_eq!(sink.messages[0].text, "committed WAL row");
    assert_eq!(bytes, before_bytes);
    assert_eq!(std::fs::read(source).unwrap(), before_main);
    assert_eq!(std::fs::read(wal).unwrap(), before_wal);
}
