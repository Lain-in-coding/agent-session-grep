//! Synthetic Antigravity sources only: JSONL and independently encoded Step
//! fields in an in-memory/disposable SQLite snapshot. No native fixture paths,
//! histories, credentials or runtime/model invocation is used.
use agent_session_grep_ports::{
    CanonicalEventSink, MetadataResolution, PortResult, ProviderAdapter, ProviderError,
    ReadOnlySource, SliceSource,
};
use agent_session_grep_provider_antigravity::{
    AntigravityAdapter, AntigravitySourceFormat, CONVERSATION_VARIANT_ID, inspect_snapshot,
    protobuf::{WireValue, decode_fields, decode_step},
};
use agent_session_grep_testkit::golden::CapturingSink;
use rusqlite::{Connection, MAIN_DB, params};
use serde_json::{Value, json};
use std::io::{BufRead, Cursor};

const CONVERSATION: &str = "10000000-0000-4000-8000-000000000001";
const TRAJECTORY: &str = "20000000-0000-4000-8000-000000000002";
const SCHEMA: &str = "
CREATE TABLE trajectory_meta(trajectory_id TEXT PRIMARY KEY,cascade_id TEXT,trajectory_type INTEGER,source INTEGER);
CREATE TABLE steps(idx INTEGER PRIMARY KEY,step_type INTEGER NOT NULL,status INTEGER NOT NULL,
 has_subtrajectory NUMERIC NOT NULL DEFAULT 0,metadata BLOB,error_details BLOB,permissions BLOB,
 task_details BLOB,render_info BLOB,step_payload BLOB,step_format INTEGER NOT NULL DEFAULT 0);
CREATE TABLE trajectory_metadata_blob(id TEXT PRIMARY KEY,data BLOB);
";

fn varint(mut number: u64) -> Vec<u8> {
    let mut encoded = Vec::new();
    while number >= 128 {
        encoded.push((number as u8 & 127) | 128);
        number >>= 7;
    }
    encoded.push(number as u8);
    encoded
}
fn scalar(field: u32, number: u64) -> Vec<u8> {
    let mut bytes = varint(u64::from(field) << 3);
    bytes.extend(varint(number));
    bytes
}
fn blob(field: u32, value: &[u8]) -> Vec<u8> {
    let mut bytes = varint((u64::from(field) << 3) | 2);
    bytes.extend(varint(value.len() as u64));
    bytes.extend_from_slice(value);
    bytes
}
fn text(field: u32, value: &str) -> Vec<u8> {
    blob(field, value.as_bytes())
}
fn step(kind: u64, status: u64, field: u32, payload: &[u8]) -> Vec<u8> {
    let mut bytes = scalar(1, kind);
    bytes.extend(scalar(4, status));
    bytes.extend(blob(field, payload));
    bytes
}
fn user(value: &str) -> Vec<u8> {
    step(14, 3, 19, &text(2, value))
}
fn planner(value: &str, id: &str) -> Vec<u8> {
    let mut payload = text(1, value);
    payload.extend(text(6, id));
    step(15, 3, 20, &payload)
}
fn initialize(conn: &Connection) {
    conn.execute_batch(SCHEMA).unwrap();
    conn.execute(
        "INSERT INTO trajectory_meta VALUES(?1,?2,4,17)",
        [TRAJECTORY, CONVERSATION],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO trajectory_metadata_blob VALUES('main',?1)",
        [text(6, CONVERSATION)],
    )
    .unwrap();
}
fn database() -> Connection {
    let db = Connection::open_in_memory().unwrap();
    initialize(&db);
    db
}
fn add(conn: &Connection, index: i64, kind: i64, status: i64, value: &[u8]) {
    conn.execute(
        "INSERT INTO steps(idx,step_type,status,step_payload) VALUES(?1,?2,?3,?4)",
        params![index, kind, status, value],
    )
    .unwrap();
}
fn image(conn: &Connection) -> Vec<u8> {
    conn.serialize(MAIN_DB).unwrap().to_vec()
}
fn json_step(index: u64, source: &str, value: &str) -> Value {
    json!({"step_index":index,"source":source,"type":"GENERIC","status":"DONE","content":value})
}
fn transcript(records: &[Value]) -> Vec<u8> {
    records
        .iter()
        .map(|record| format!("{record}\n"))
        .collect::<String>()
        .into_bytes()
}

#[test]
fn transcript_step_identity_is_separate_from_dense_emitted_seq_and_native_identity() {
    let bytes = transcript(&[
        json_step(0, "USER_EXPLICIT", "  中文原文\n保留  "),
        json!({"step_index":1,"source":"SYSTEM","type":"CONVERSATION_HISTORY","status":"DONE","content":"context metadata"}),
        json_step(2, "MODEL", "Exact assistant text"),
    ]);
    let before = bytes.clone();
    let mut sink = CapturingSink::default();
    let observed = AntigravityAdapter::new()
        .parse_with_steps(&bytes, &mut sink)
        .unwrap();
    assert!(observed.complete);
    assert_eq!(observed.report.skipped, 0);
    assert_eq!(observed.format, AntigravitySourceFormat::TranscriptJsonl);
    assert_eq!(
        observed
            .steps
            .iter()
            .map(|e| (e.seq, e.step_index))
            .collect::<Vec<_>>(),
        [(0, 0), (1, 2)]
    );
    assert_eq!(sink.messages[0].text, "  中文原文\n保留  ");
    assert!(
        sink.messages
            .iter()
            .all(|message| message.native_id.is_empty())
    );
    for evidence in observed.steps {
        let (start, end) = evidence.span.unwrap();
        let record: Value = serde_json::from_slice(&bytes[start as usize..end as usize]).unwrap();
        assert_eq!(record["step_index"], evidence.step_index);
        assert_eq!(
            sink.messages[evidence.seq as usize].span,
            Some((start, end))
        );
    }
    assert_eq!(observed.report.session_native_id, None);
    assert_eq!(bytes, before);
}

#[test]
fn transcript_truncated_fields_never_publish_shortened_text_even_if_another_field_is_full() {
    for fields in [
        json!(["content"]),
        json!(["thinking"]),
        json!(["future_field"]),
    ] {
        let mut bad = json_step(1, "MODEL", "shortened body must not emit");
        bad["thinking"] = json!("apparently complete alternate field");
        bad["truncated_fields"] = fields;
        let bytes = transcript(&[
            json_step(0, "USER_EXPLICIT", "complete prefix"),
            bad,
            json_step(2, "MODEL", "complete suffix"),
        ]);
        let mut sink = CapturingSink::default();
        let observed = AntigravityAdapter::new()
            .parse_with_steps(&bytes, &mut sink)
            .unwrap();
        assert!(!observed.complete);
        assert_eq!(observed.report.skipped, 1);
        assert_eq!(
            observed
                .steps
                .iter()
                .map(|e| e.step_index)
                .collect::<Vec<_>>(),
            [0, 2]
        );
        assert_eq!(
            sink.messages
                .iter()
                .map(|e| e.text.as_str())
                .collect::<Vec<_>>(),
            ["complete prefix", "complete suffix"]
        );
    }
    let mut complete = json_step(0, "MODEL", "whole body");
    complete["truncated_fields"] = json!([]);
    let observed = AntigravityAdapter::new()
        .parse_with_steps(&transcript(&[complete]), &mut CapturingSink::default())
        .unwrap();
    assert!(observed.complete);
}

#[test]
fn malformed_truncation_or_identity_shapes_and_nonterminal_steps_are_incomplete() {
    let base = json_step(0, "MODEL", "must not emit");
    let mut cases = Vec::new();
    for invalid in [json!(-1), json!("0"), json!(0.5), Value::Null] {
        let mut value = base.clone();
        value["step_index"] = invalid;
        cases.push(value);
    }
    for invalid in [json!(true), json!({"content":true}), json!([1])] {
        let mut value = base.clone();
        value["truncated_fields"] = invalid;
        cases.push(value);
    }
    for status in ["RUNNING", "PENDING", "FUTURE_STATUS"] {
        let mut value = base.clone();
        value["status"] = json!(status);
        cases.push(value);
    }
    let mut missing = base.clone();
    missing.as_object_mut().unwrap().remove("status");
    cases.push(missing);
    let mut unknown = base;
    unknown["type"] = json!("UNKNOWN_NATIVE_TYPE");
    cases.push(unknown);
    for value in cases {
        let mut sink = CapturingSink::default();
        let observed = AntigravityAdapter::new()
            .parse_with_steps(&transcript(&[value]), &mut sink)
            .unwrap();
        assert!(!observed.complete);
        assert_eq!(observed.report.skipped, 1);
        assert!(sink.messages.is_empty());
    }
}

#[test]
fn duplicate_out_of_order_and_chunk_gaps_cannot_establish_complete_observation() {
    for indices in [[0, 0, 1], [0, 2, 1], [1, 2, 3], [0, 2, 3]] {
        let bytes = transcript(
            &indices
                .into_iter()
                .map(|index| json_step(index, "MODEL", "synthetic step"))
                .collect::<Vec<_>>(),
        );
        let mut sink = CapturingSink::default();
        let observed = AntigravityAdapter::new()
            .parse_with_steps(&bytes, &mut sink)
            .unwrap();
        assert!(!observed.complete, "indices={indices:?}");
        assert!(
            observed
                .steps
                .windows(2)
                .all(|pair| pair[0].step_index < pair[1].step_index)
        );
        assert!(
            sink.messages
                .iter()
                .enumerate()
                .all(|(seq, value)| value.seq == seq as u32)
        );
    }
}

#[test]
fn diagnostics_are_bounded_and_do_not_echo_source_values() {
    let bytes = (0..100).map(|index| format!("{{\"step_index\":{index},\"source\":\"sensitive diagnostic marker\",\"thinking\":{{\"echo\":\"must stay out\"}}}}\n")).collect::<String>();
    let observed = AntigravityAdapter::new()
        .parse_with_steps(bytes.as_bytes(), &mut CapturingSink::default())
        .unwrap();
    assert!(!observed.complete);
    assert_eq!(observed.report.skipped, 100);
    assert!(observed.report.diagnostics.len() <= 64);
    let diagnostics = observed.report.diagnostics.join(" ");
    assert!(!diagnostics.contains("sensitive diagnostic marker"));
    assert!(!diagnostics.contains("must stay out"));
}

#[test]
fn bounded_wire_scalars_nonascii_and_exact_field_ranges() {
    let mut bytes = scalar(1, u64::MAX);
    bytes.extend(varint((2 << 3) | 1));
    bytes.extend(u64::MAX.to_le_bytes());
    bytes.extend(text(3, "中文\nαβ exact"));
    bytes.extend(varint((4 << 3) | 5));
    bytes.extend(u32::MAX.to_le_bytes());
    let before = bytes.clone();
    let values = decode_fields(&bytes).unwrap();
    assert_eq!(values[0].value, WireValue::Varint(u64::MAX));
    assert_eq!(values[1].value, WireValue::Fixed64(u64::MAX));
    assert_eq!(
        values[2].value,
        WireValue::Bytes("中文\nαβ exact".as_bytes())
    );
    assert_eq!(values[3].value, WireValue::Fixed32(u32::MAX));
    let (start, end) = values[2].value_span;
    assert_eq!(
        &bytes[start as usize..end as usize],
        "中文\nαβ exact".as_bytes()
    );
    assert!(
        values
            .windows(2)
            .all(|pair| pair[0].span.1 == pair[1].span.0)
    );
    assert_eq!(values.last().unwrap().span.1, bytes.len() as u64);
    assert_eq!(bytes, before);
}

#[test]
fn malformed_wire_never_panics_or_turns_readable_unknown_strings_into_chat() {
    let mut cases = vec![
        vec![0],
        vec![8, 128],
        vec![8, 128, 0],
        vec![11],
        vec![12],
        vec![14],
        vec![9, 1],
        vec![13, 1],
        vec![18, 9, 1],
    ];
    let mut overflow = vec![8];
    overflow.extend([255; 10]);
    cases.push(overflow);
    for bytes in cases {
        assert!(
            std::panic::catch_unwind(|| decode_fields(&bytes))
                .unwrap()
                .is_err()
        );
    }
    let mut unknown = scalar(1, 999);
    unknown.extend(scalar(4, 3));
    unknown.extend(text(222, "human readable but unverified"));
    let step = decode_step(&unknown).unwrap();
    assert!(!step.supported);
    assert!(step.role.is_none());
    assert!(step.text.is_none());
    let mut sink = CapturingSink::default();
    let observed = AntigravityAdapter::new()
        .parse_protobuf_step(&unknown, 12, &mut sink)
        .unwrap();
    assert!(!observed.complete);
    assert_eq!(observed.report.skipped, 1);
    assert!(sink.messages.is_empty());
}

#[test]
fn step_nested_spans_and_actual_native_planner_id_are_preserved() {
    let bytes = planner("  original 中文\nassistant text  ", "stored-message-alpha");
    let decoded = decode_step(&bytes).unwrap();
    assert_eq!(decoded.native_message_id, Some("stored-message-alpha"));
    let (start, end) = decoded.text_span.unwrap();
    assert_eq!(
        &bytes[start as usize..end as usize],
        decoded.text.unwrap().as_bytes()
    );
    let mut sink = CapturingSink::default();
    let observed = AntigravityAdapter::new()
        .parse_protobuf_step(&bytes, 42, &mut sink)
        .unwrap();
    assert!(observed.complete);
    assert_eq!(observed.steps[0].step_index, 42);
    assert_eq!(observed.steps[0].seq, 0);
    assert_eq!(sink.messages[0].native_id, "stored-message-alpha");
    assert_eq!(sink.messages[0].span, Some((0, bytes.len() as u64)));
    assert_eq!(sink.messages[0].text, "  original 中文\nassistant text  ");
    assert_eq!(observed.report.session_native_id, None);
}

#[test]
fn duplicate_singular_fields_ambiguous_payload_utf8_and_missing_type_fail_closed() {
    let mut duplicate_type = user("source");
    duplicate_type.extend(scalar(1, 14));
    let mut duplicate_text = text(2, "first");
    duplicate_text.extend(text(2, "second"));
    let mut ambiguous = user("source");
    ambiguous.extend(blob(20, &text(1, "assistant")));
    for bytes in [
        duplicate_type,
        step(14, 3, 19, &duplicate_text),
        ambiguous,
        step(14, 3, 19, &blob(2, &[255])),
        scalar(4, 3),
    ] {
        assert!(decode_step(&bytes).is_err());
    }
}

#[test]
fn wire_field_count_and_length_limits_are_enforced_without_large_allocations() {
    let many = (0..16_385).flat_map(|_| scalar(101, 1)).collect::<Vec<_>>();
    assert!(decode_fields(&many).is_err());
    let mut oversized = varint((9 << 3) | 2);
    oversized.extend(varint(8 * 1024 * 1024 + 1));
    assert!(matches!(
        decode_fields(&oversized),
        Err(ProviderError::RecordTooLarge { .. })
    ));
}

#[test]
fn db_only_history_is_original_source_text_with_observed_session_id() {
    let db = database();
    add(&db, 0, 14, 3, &user(" first DB-only 中文 request\n"));
    add(
        &db,
        1,
        15,
        3,
        &planner("DB-only exact assistant reply", "native-database-message"),
    );
    let bytes = image(&db);
    let before = bytes.clone();
    let mut sink = CapturingSink::default();
    let adapter = AntigravityAdapter::new();
    assert_eq!(
        adapter
            .probe_source(&SliceSource::new(&bytes))
            .unwrap()
            .variant_id,
        CONVERSATION_VARIANT_ID
    );
    let observed = adapter
        .parse_source_with_steps(&SliceSource::new(&bytes), &mut sink)
        .unwrap();
    assert!(observed.complete);
    assert_eq!(observed.report.committed, 2);
    assert_eq!(observed.report.skipped, 0);
    assert_eq!(observed.format, AntigravitySourceFormat::ConversationSqlite);
    assert_eq!(
        observed.report.session_native_id.as_deref(),
        Some(CONVERSATION)
    );
    assert_eq!(
        observed.report.session_observation.provider_session_id,
        MetadataResolution::Resolved(CONVERSATION.into())
    );
    assert_eq!(
        observed
            .report
            .session_observation
            .original_working_directory,
        MetadataResolution::Missing
    );
    assert!(!observed.report.session_observation.pair_observed);
    assert_eq!(sink.messages[0].text, " first DB-only 中文 request\n");
    assert!(sink.messages[0].native_id.is_empty());
    assert_eq!(sink.messages[1].native_id, "native-database-message");
    assert!(
        sink.messages
            .iter()
            .all(|message| message.span.is_none() && message.timestamp.is_none())
    );
    assert_eq!(bytes, before);
}

#[test]
fn db_unknown_types_status_encoding_and_nested_trajectories_remain_incomplete() {
    for mode in 0..4 {
        let db = database();
        add(&db, 0, 14, 3, &user("known prefix"));
        let (kind, status, bytes) = match mode {
            0 => (999, 3, {
                let mut bytes = scalar(1, 999);
                bytes.extend(scalar(4, 3));
                bytes.extend(text(55, "not chat"));
                bytes
            }),
            1 => (15, 1, step(15, 1, 20, &text(1, "pending body"))),
            _ => (15, 3, planner("unavailable body", "stored-message")),
        };
        add(&db, 1, kind, status, &bytes);
        if mode == 2 {
            db.execute("UPDATE steps SET step_format=5 WHERE idx=1", [])
                .unwrap();
        }
        if mode == 3 {
            db.execute("UPDATE steps SET has_subtrajectory=1 WHERE idx=1", [])
                .unwrap();
        }
        let mut sink = CapturingSink::default();
        let observed = AntigravityAdapter::new()
            .parse_with_steps(&image(&db), &mut sink)
            .unwrap();
        assert!(!observed.complete);
        assert_eq!(observed.report.skipped, 1);
        assert_eq!(observed.report.committed, 1);
        assert_eq!(sink.messages[0].text, "known prefix");
    }
}

#[test]
fn db_row_wire_scalar_mismatch_or_late_corruption_emits_no_prefix() {
    for mode in 0..4 {
        let db = database();
        add(&db, 0, 14, 3, &user("must not escape corrupt source"));
        add(&db, 1, 15, 3, &planner("later body", "stored-message"));
        match mode {
            0 => {
                db.execute("UPDATE steps SET step_type=14 WHERE idx=1", [])
                    .unwrap();
            }
            1 => {
                db.execute("UPDATE steps SET status=7 WHERE idx=1", [])
                    .unwrap();
            }
            2 => {
                db.execute(
                    "UPDATE steps SET step_payload=?1 WHERE idx=1",
                    [vec![8, 128]],
                )
                .unwrap();
            }
            _ => {
                db.execute("UPDATE steps SET idx=4 WHERE idx=1", [])
                    .unwrap();
            }
        }
        let mut sink = CapturingSink::default();
        assert!(
            AntigravityAdapter::new()
                .parse_with_steps(&image(&db), &mut sink)
                .is_err()
        );
        assert!(sink.messages.is_empty());
    }
}

#[test]
fn db_identity_is_validated_from_records_and_never_fabricated_from_container() {
    for mode in 0..4 {
        let db = database();
        add(&db, 0, 14, 3, &user("verified content"));
        match mode {
            0 => {
                db.execute("UPDATE trajectory_meta SET cascade_id='not-native-id'", [])
                    .unwrap();
            }
            1 => {
                db.execute("UPDATE trajectory_meta SET source=0", [])
                    .unwrap();
            }
            2 => {
                db.execute(
                    "INSERT INTO trajectory_meta VALUES(?1,?2,4,17)",
                    ["30000000-0000-4000-8000-000000000003", CONVERSATION],
                )
                .unwrap();
            }
            _ => {
                db.execute(
                    "UPDATE trajectory_metadata_blob SET data=?1",
                    [text(6, "40000000-0000-4000-8000-000000000004")],
                )
                .unwrap();
            }
        }
        let mut sink = CapturingSink::default();
        let error = AntigravityAdapter::new()
            .parse_with_steps(&image(&db), &mut sink)
            .unwrap_err();
        assert!(!error.to_string().contains(CONVERSATION));
        assert!(sink.messages.is_empty());
    }
}

#[test]
fn empty_verified_database_is_distinct_from_empty_or_unknown_input() {
    let db = database();
    let observed = AntigravityAdapter::new()
        .parse_with_steps(&image(&db), &mut CapturingSink::default())
        .unwrap();
    assert!(observed.complete);
    assert_eq!(observed.report.committed, 0);
    let empty = AntigravityAdapter::new()
        .parse_with_steps(b"", &mut CapturingSink::default())
        .unwrap();
    assert!(!empty.complete);
    for bytes in [b"opaque conversation .pb".as_slice(), &[255, 192, 3, 7]] {
        let mut sink = CapturingSink::default();
        let result = AntigravityAdapter::new().parse_with_steps(bytes, &mut sink);
        assert!(result.is_err() || !result.unwrap().complete);
        assert!(sink.messages.is_empty());
    }
}

#[test]
fn generic_tools_are_validated_metadata_not_chat_or_fabricated_activities() {
    let db = database();
    let mut args = text(1, "tool_name");
    args.extend(text(2, "synthetic_tool"));
    let mut payload = blob(1, &args);
    payload.extend(blob(2, &text(1, "tool result should not be chat")));
    add(&db, 0, 132, 7, &step(132, 7, 140, &payload));
    let mut sink = CapturingSink::default();
    let observed = AntigravityAdapter::new()
        .parse_with_steps(&image(&db), &mut sink)
        .unwrap();
    assert!(observed.complete);
    assert_eq!(observed.report.committed, 0);
    assert!(sink.messages.is_empty());
    assert!(sink.activities.is_empty());
    assert!(sink.usages.is_empty());
}

#[test]
fn snapshot_repeatability_append_and_same_size_text_rewrite_use_current_bytes() {
    let db = database();
    add(&db, 0, 14, 3, &user("alpha"));
    let original = image(&db);
    db.execute(
        "UPDATE steps SET step_payload=?1 WHERE idx=0",
        [user("bravo")],
    )
    .unwrap();
    let rewritten = image(&db);
    assert_eq!(original.len(), rewritten.len());
    add(
        &db,
        1,
        15,
        3,
        &planner("append after snapshot", "new-message"),
    );
    let appended = image(&db);
    for (bytes, expected) in [
        (&original, "alpha"),
        (&rewritten, "bravo"),
        (&original, "alpha"),
    ] {
        let mut sink = CapturingSink::default();
        let observed = AntigravityAdapter::new()
            .parse_with_steps(bytes, &mut sink)
            .unwrap();
        assert!(observed.complete);
        assert_eq!(observed.report.committed, 1);
        assert_eq!(sink.messages[0].text, expected);
    }
    let mut sink = CapturingSink::default();
    let observed = AntigravityAdapter::new()
        .parse_with_steps(&appended, &mut sink)
        .unwrap();
    assert!(observed.complete);
    assert_eq!(sink.messages.len(), 2);
}

#[test]
fn invalid_sqlite_version_flags_and_malformed_page_bounds_are_rejected() {
    let db = database();
    let original = image(&db);
    for versions in [[0, 0], [1, 2], [2, 1], [3, 3]] {
        let mut bytes = original.clone();
        bytes[18..20].copy_from_slice(&versions);
        assert!(
            AntigravityAdapter::new()
                .parse_with_steps(&bytes, &mut CapturingSink::default())
                .is_err()
        );
    }
    let mut truncated = original.clone();
    truncated.pop();
    assert!(
        AntigravityAdapter::new()
            .parse_with_steps(&truncated, &mut CapturingSink::default())
            .is_err()
    );
    let mut malformed = original;
    malformed[16..18].copy_from_slice(&[0, 3]);
    assert!(
        AntigravityAdapter::new()
            .parse_with_steps(&malformed, &mut CapturingSink::default())
            .is_err()
    );
}

struct SyntheticScratch {
    root: std::path::PathBuf,
}
impl SyntheticScratch {
    fn new() -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let base = std::env::temp_dir();
        for _ in 0..100 {
            let index = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let nonce = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let root = base.join(format!("asg-antigravity-synthetic-{nonce}-{index}"));
            match std::fs::create_dir(&root) {
                Ok(()) => return Self { root },
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!(
                    "synthetic scratch directory could not be reserved: {:?}",
                    error.kind()
                ),
            }
        }
        panic!("synthetic scratch directory collision limit exceeded");
    }
}
impl Drop for SyntheticScratch {
    fn drop(&mut self) {
        // Only this test's explicitly named synthetic files; no recursive move
        // or delete of a computed directory and no source/home path traversal.
        for name in ["synthetic.db", "synthetic.db-wal", "synthetic.db-shm"] {
            let _ = std::fs::remove_file(self.root.join(name));
        }
        let _ = std::fs::remove_dir(&self.root);
    }
}

#[test]
fn actual_wal_backup_header_two_is_readable_without_modifying_source_or_snapshot_bytes() {
    let scratch = SyntheticScratch::new();
    let source_path = scratch.root.join("synthetic.db");
    let source = Connection::open(&source_path).unwrap();
    source
        .execute_batch("PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0")
        .unwrap();
    initialize(&source);
    source
        .execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")
        .unwrap();
    add(&source, 0, 14, 3, &user("committed only in WAL 中文"));
    let main_before = std::fs::read(&source_path).unwrap();
    let wal_before = std::fs::read(scratch.root.join("synthetic.db-wal")).unwrap();
    assert!(wal_before.len() > 32);
    let mut destination = Connection::open_in_memory().unwrap();
    {
        let backup = rusqlite::backup::Backup::new(&source, &mut destination).unwrap();
        assert_eq!(backup.step(-1).unwrap(), rusqlite::backup::StepResult::Done);
    }
    let bytes = image(&destination);
    assert_eq!(&bytes[18..20], &[2, 2]);
    let before = bytes.clone();
    let mut sink = CapturingSink::default();
    let observed = AntigravityAdapter::new()
        .parse_with_steps(&bytes, &mut sink)
        .unwrap();
    assert_eq!(inspect_snapshot(&bytes).unwrap(), observed);
    assert!(observed.complete);
    assert_eq!(observed.report.committed, 1);
    assert_eq!(sink.messages[0].text, "committed only in WAL 中文");
    assert_eq!(bytes, before);
    assert_eq!(std::fs::read(&source_path).unwrap(), main_before);
    assert_eq!(
        std::fs::read(scratch.root.join("synthetic.db-wal")).unwrap(),
        wal_before
    );
}

struct OversizedSnapshot;
impl ReadOnlySource for OversizedSnapshot {
    fn len(&self) -> u64 {
        128 * 1024 * 1024 + 1
    }
    fn open(&self) -> PortResult<Box<dyn BufRead + Send + '_>> {
        Ok(Box::new(Cursor::new(b"SQLite format 3\0")))
    }
}
#[test]
fn source_snapshot_limit_is_checked_before_full_read_or_allocation() {
    assert!(matches!(
        AntigravityAdapter::new()
            .parse_source_with_steps(&OversizedSnapshot, &mut CapturingSink::default()),
        Err(ProviderError::SourceTooLarge { .. })
    ));
}

#[test]
fn mapped_empty_text_and_visible_thinking_fallback_match_existing_jsonl_policy() {
    let db = database();
    add(&db, 0, 14, 3, &step(14, 3, 19, &text(2, "   ")));
    let mut payload = text(1, " ");
    payload.extend(text(3, "visible trace only"));
    add(&db, 1, 15, 3, &step(15, 3, 20, &payload));
    let mut sink = CapturingSink::default();
    let observed = AntigravityAdapter::new()
        .parse_with_steps(&image(&db), &mut sink)
        .unwrap();
    assert!(observed.complete);
    assert_eq!(observed.report.committed, 1);
    assert_eq!(sink.messages[0].text, "visible trace only");
    assert_eq!(observed.steps[0].step_index, 1);
}

#[test]
fn protobuf_unknown_field_nesting_is_not_recursively_interpreted() {
    let mut opaque = text(1, "readable metadata must not be chat");
    for _ in 0..300 {
        opaque = blob(99, &opaque);
    }
    let mut bytes = user("actual source body");
    bytes.extend(blob(333, &opaque));
    let value = decode_step(&bytes).unwrap();
    assert_eq!(value.text, Some("actual source body"));
    assert!(value.supported);
}

struct RejectingSink;
impl CanonicalEventSink for RejectingSink {
    fn emit_message(&mut self, _: agent_session_grep_ports::MessageEvent<'_>) -> PortResult<()> {
        Err(agent_session_grep_ports::PortError::SourceIo(
            "sensitive sink details".into(),
        ))
    }
}
#[test]
fn sink_errors_preserve_failure_without_disclosing_details() {
    let error = AntigravityAdapter::new()
        .parse_protobuf_step(&user("source body"), 0, &mut RejectingSink)
        .unwrap_err();
    assert!(!error.to_string().contains("sensitive sink details"));
}

#[test]
fn thirteen_synthetic_db_only_sessions_parse_independently_without_transcript_or_summary() {
    // The count mirrors the documented coverage gap, not private source data.
    // Every identity and body below is generated solely from synthetic labels.
    let adapter = AntigravityAdapter::new();
    let mut sessions = std::collections::BTreeSet::new();
    let mut committed = 0usize;
    for number in 1..=13 {
        let db = database();
        let conversation = format!("10000000-0000-4000-8000-{number:012}");
        let trajectory = format!("20000000-0000-4000-8000-{number:012}");
        db.execute(
            "UPDATE trajectory_meta SET trajectory_id=?1,cascade_id=?2",
            [&trajectory, &conversation],
        )
        .unwrap();
        db.execute(
            "UPDATE trajectory_metadata_blob SET data=?1",
            [text(6, &conversation)],
        )
        .unwrap();
        let request = format!("合成 DB-only {number}: preserve the exact source text\n");
        let reply = format!("synthetic reply {number}: original 中文 text");
        let native_message = format!("synthetic-stored-message-{number}");
        add(&db, 0, 14, 3, &user(&request));
        let generic_result = blob(2, &text(1, "tool metadata is not another message"));
        add(&db, 1, 132, 3, &step(132, 3, 140, &generic_result));
        add(&db, 2, 15, 3, &planner(&reply, &native_message));
        let bytes = image(&db);
        let before = bytes.clone();
        let mut sink = CapturingSink::default();
        let observed = adapter
            .parse_source_with_steps(&SliceSource::new(&bytes), &mut sink)
            .unwrap();
        assert_eq!(inspect_snapshot(&bytes).unwrap(), observed);
        assert!(observed.complete);
        assert_eq!(observed.report.skipped, 0);
        assert_eq!(observed.report.committed, 2);
        assert_eq!(
            observed.report.session_native_id.as_deref(),
            Some(conversation.as_str())
        );
        assert!(sessions.insert(observed.report.session_native_id.unwrap()));
        assert_eq!(
            observed
                .steps
                .iter()
                .map(|e| (e.seq, e.step_index))
                .collect::<Vec<_>>(),
            [(0, 0), (1, 2)]
        );
        assert_eq!(sink.messages[0].text, request);
        assert_eq!(sink.messages[1].text, reply);
        assert_eq!(sink.messages[1].native_id, native_message);
        assert!(sink.messages[0].native_id.is_empty());
        assert!(sink.messages.iter().all(|message| message.span.is_none()));
        assert!(sink.activities.is_empty());
        assert!(sink.usages.is_empty());
        assert_eq!(bytes, before);
        committed += observed.report.committed;
    }
    assert_eq!(sessions.len(), 13);
    assert_eq!(committed, 26);
}

#[test]
fn full_truncated_and_chunk_snapshots_keep_step_evidence_without_claiming_cross_file_dedup() {
    // Synthetic reproduction of the documented representation sizes only.
    // Choosing transcript_full and excluding chunk/mirror files belongs to
    // discovery; a parser receiving bytes cannot certify their filename.
    let full_records = (0..125)
        .map(|index| {
            let source = if index % 2 == 0 {
                "USER_EXPLICIT"
            } else {
                "MODEL"
            };
            json_step(
                index,
                source,
                &format!("full original step {index}: 中文 exact\nbody"),
            )
        })
        .collect::<Vec<_>>();
    let mut short_records = full_records.clone();
    for index in (0..14).map(|number| number * 8) {
        short_records[index]["content"] = json!("truncated mirror must not replace full source");
        short_records[index]["truncated_fields"] = json!(["content"]);
    }
    let chunk_records = full_records
        .iter()
        .enumerate()
        .filter(|(index, _)| *index != 63)
        .map(|(_, value)| value.clone())
        .collect::<Vec<_>>();
    for (full, shorter) in full_records.iter().zip(&short_records) {
        assert_eq!(full["step_index"], shorter["step_index"]);
        assert_eq!(full["type"], shorter["type"]);
        assert_eq!(full["source"], shorter["source"]);
    }
    let full_bytes = transcript(&full_records);
    let shorter_bytes = transcript(&short_records);
    let chunk_bytes = transcript(&chunk_records);
    let adapter = AntigravityAdapter::new();
    let mut full_sink = CapturingSink::default();
    let mut short_sink = CapturingSink::default();
    let mut chunk_sink = CapturingSink::default();
    let full = adapter
        .parse_with_steps(&full_bytes, &mut full_sink)
        .unwrap();
    let shorter = adapter
        .parse_with_steps(&shorter_bytes, &mut short_sink)
        .unwrap();
    let chunk = adapter
        .parse_with_steps(&chunk_bytes, &mut chunk_sink)
        .unwrap();
    assert!(full.complete && full.report.skipped == 0);
    assert_eq!(full.report.committed, 125);
    assert!(!shorter.complete);
    assert_eq!(shorter.report.skipped, 14);
    assert_eq!(shorter.report.committed, 111);
    assert!(!chunk.complete);
    assert_eq!(chunk.report.skipped, 0);
    assert_eq!(chunk.report.committed, 124);
    for evidence in shorter.steps.iter().chain(&chunk.steps) {
        assert!(
            full.steps
                .iter()
                .any(|full_evidence| full_evidence.step_index == evidence.step_index)
        );
    }
    for (observation, sink, bytes) in [
        (&full, &full_sink, &full_bytes),
        (&shorter, &short_sink, &shorter_bytes),
        (&chunk, &chunk_sink, &chunk_bytes),
    ] {
        assert!(observation.report.session_native_id.is_none());
        assert!(
            sink.messages
                .iter()
                .all(|message| message.native_id.is_empty())
        );
        for evidence in &observation.steps {
            let (start, end) = evidence.span.unwrap();
            let record: Value =
                serde_json::from_slice(&bytes[start as usize..end as usize]).unwrap();
            assert_eq!(record["step_index"], evidence.step_index);
            assert_eq!(
                record["content"].as_str(),
                Some(sink.messages[evidence.seq as usize].text.as_str())
            );
        }
    }
    // Repeating the same complete snapshot must yield all its records. Hidden
    // process-global dedup would lose evidence during re-observation/rewrite.
    let repeated = adapter
        .parse_with_steps(&full_bytes, &mut CapturingSink::default())
        .unwrap();
    assert_eq!(repeated, full);
}

#[test]
fn inspection_returns_only_source_evidence_and_uses_full_parse_validity() {
    let bytes = transcript(&[
        json_step(0, "USER_EXPLICIT", "synthetic visible source body"),
        json_step(1, "MODEL", "synthetic original response"),
    ]);
    let before = bytes.clone();
    let inspected = inspect_snapshot(&bytes).unwrap();
    assert!(inspected.complete);
    assert_eq!(inspected.format, AntigravitySourceFormat::TranscriptJsonl);
    assert_eq!(inspected.report.committed, 2);
    assert_eq!(
        inspected
            .steps
            .iter()
            .map(|e| (e.seq, e.step_index))
            .collect::<Vec<_>>(),
        [(0, 0), (1, 1)]
    );
    assert!(inspected.report.session_native_id.is_none());
    let evidence = format!("{inspected:?}");
    assert!(!evidence.contains("synthetic visible source body"));
    assert!(!evidence.contains("synthetic original response"));
    assert_eq!(bytes, before);

    let mut truncated = json_step(0, "MODEL", "shortened data must remain incomplete");
    truncated["truncated_fields"] = json!(["content"]);
    let incomplete = inspect_snapshot(&transcript(&[truncated])).unwrap();
    assert!(!incomplete.complete);
    assert_eq!(incomplete.report.skipped, 1);
    assert_eq!(incomplete.report.committed, 0);
    assert!(incomplete.steps.is_empty());
    let empty = inspect_snapshot(b"").unwrap();
    assert!(!empty.complete);
    assert!(inspect_snapshot(&[255, 192, 3]).is_err());

    let db = database();
    add(&db, 0, 14, 3, &user("database-only synthetic body"));
    let inspected = inspect_snapshot(&image(&db)).unwrap();
    assert!(inspected.complete);
    assert_eq!(
        inspected.format,
        AntigravitySourceFormat::ConversationSqlite
    );
    assert_eq!(
        inspected.report.session_native_id.as_deref(),
        Some(CONVERSATION)
    );
    assert_eq!(inspected.report.committed, 1);
    assert!(!format!("{inspected:?}").contains("database-only synthetic body"));
}

#[test]
fn inspection_cannot_promote_unknown_or_late_corrupt_database_steps_to_complete() {
    let db = database();
    add(&db, 0, 14, 3, &user("known DB-only prefix"));
    let mut unknown = scalar(1, 777);
    unknown.extend(scalar(4, 3));
    unknown.extend(text(55, "readable metadata is not verified conversation"));
    add(&db, 1, 777, 3, &unknown);
    let inspected = inspect_snapshot(&image(&db)).unwrap();
    assert!(!inspected.complete);
    assert_eq!(inspected.report.skipped, 1);
    assert_eq!(inspected.report.committed, 1);
    assert_eq!(inspected.steps[0].step_index, 0);
    assert!(!format!("{inspected:?}").contains("readable metadata"));

    db.execute(
        "UPDATE steps SET step_payload=?1 WHERE idx=1",
        [vec![8, 128]],
    )
    .unwrap();
    assert!(inspect_snapshot(&image(&db)).is_err());
}

fn future_deadline() -> std::time::Instant {
    std::time::Instant::now() + std::time::Duration::from_secs(2)
}
fn assert_deadline(error: ProviderError) {
    assert_eq!(
        error,
        ProviderError::StructuralFatal("Antigravity deadline exceeded".into())
    );
}
fn wait_past(end: std::time::Instant) {
    // This synthetic delay deliberately consumes the caller's original budget,
    // without assigning a new deadline after any read/SQL/sink stage.
    std::thread::sleep(
        end.saturating_duration_since(std::time::Instant::now())
            + std::time::Duration::from_millis(2),
    );
}

struct NeverOpened(std::sync::atomic::AtomicUsize);
impl ReadOnlySource for NeverOpened {
    fn len(&self) -> u64 {
        0
    }
    fn open(&self) -> PortResult<Box<dyn BufRead + Send + '_>> {
        self.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Err(agent_session_grep_ports::PortError::SourceIo(
            "synthetic open must not be reached".into(),
        ))
    }
}
#[test]
fn original_deadline_expired_before_source_open_or_step_decode_rejects_without_emission() {
    let end = std::time::Instant::now() - std::time::Duration::from_secs(1);
    let source = NeverOpened(std::sync::atomic::AtomicUsize::new(0));
    let mut sink = CapturingSink::default();
    let error = AntigravityAdapter::new()
        .parse_source_with_steps_deadline(&source, &mut sink, end)
        .unwrap_err();
    assert_deadline(error);
    assert_eq!(source.0.load(std::sync::atomic::Ordering::Relaxed), 0);
    assert!(sink.messages.is_empty());
    let error = AntigravityAdapter::new()
        .parse_protobuf_step_deadline(&user("synthetic step"), 0, &mut sink, end)
        .unwrap_err();
    assert_deadline(error);
    assert!(sink.messages.is_empty());
}

struct DelayedChunkSource<'a> {
    bytes: &'a [u8],
    first_chunk: usize,
    end: std::time::Instant,
    opened: std::sync::atomic::AtomicUsize,
    delayed: std::sync::atomic::AtomicUsize,
}
impl ReadOnlySource for DelayedChunkSource<'_> {
    fn len(&self) -> u64 {
        self.bytes.len() as u64
    }
    fn open(&self) -> PortResult<Box<dyn BufRead + Send + '_>> {
        let opened = self
            .opened
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if opened == 0 {
            // Header classification reads the same immutable bytes, with no
            // deliberate pause. The actual parser's read is paused mid-source.
            return Ok(Box::new(Cursor::new(self.bytes)));
        }
        Ok(Box::new(DelayedChunkReader {
            source: self,
            position: 0,
            did_delay: false,
        }))
    }
}
struct DelayedChunkReader<'a> {
    source: &'a DelayedChunkSource<'a>,
    position: usize,
    did_delay: bool,
}
impl std::io::Read for DelayedChunkReader<'_> {
    fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
        let available = self.fill_buf()?;
        let length = available.len().min(output.len());
        output[..length].copy_from_slice(&available[..length]);
        self.consume(length);
        Ok(length)
    }
}
impl BufRead for DelayedChunkReader<'_> {
    fn fill_buf(&mut self) -> std::io::Result<&[u8]> {
        if self.position >= self.source.first_chunk && !self.did_delay {
            self.source
                .delayed
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            self.did_delay = true;
            wait_past(self.source.end);
        }
        let end = if self.position < self.source.first_chunk {
            self.source.first_chunk.min(self.source.bytes.len())
        } else {
            self.source.bytes.len()
        };
        Ok(&self.source.bytes[self.position..end])
    }
    fn consume(&mut self, length: usize) {
        self.position += length;
    }
}
#[test]
fn original_deadline_during_jsonl_read_rejects_after_one_prefix_without_complete_observation() {
    let bytes = transcript(&[
        json_step(0, "USER_EXPLICIT", "prefix"),
        json_step(1, "MODEL", "must not emit after deadline"),
    ]);
    let source = DelayedChunkSource {
        bytes: &bytes,
        first_chunk: bytes.iter().position(|byte| *byte == b'\n').unwrap() + 1,
        end: future_deadline(),
        opened: std::sync::atomic::AtomicUsize::new(0),
        delayed: std::sync::atomic::AtomicUsize::new(0),
    };
    let before = bytes.clone();
    let mut sink = CapturingSink::default();
    assert_deadline(
        AntigravityAdapter::new()
            .parse_source_with_steps_deadline(&source, &mut sink, source.end)
            .unwrap_err(),
    );
    assert_eq!(source.delayed.load(std::sync::atomic::Ordering::Relaxed), 1);
    assert_eq!(sink.messages.len(), 1);
    assert_eq!(sink.messages[0].text, "prefix");
    assert_eq!(bytes, before);
    // This prefix is staging only: the error returned no observation or source
    // completion proof, so callers must discard it rather than publish it.
}
#[test]
fn original_deadline_during_sqlite_snapshot_read_rejects_before_any_message() {
    let db = database();
    add(
        &db,
        0,
        14,
        3,
        &user(&"synthetic bounded read block ".repeat(4000)),
    );
    let bytes = image(&db);
    let before = bytes.clone();
    let source = DelayedChunkSource {
        bytes: &bytes,
        first_chunk: 4096,
        end: future_deadline(),
        opened: std::sync::atomic::AtomicUsize::new(0),
        delayed: std::sync::atomic::AtomicUsize::new(0),
    };
    let mut sink = CapturingSink::default();
    assert_deadline(
        AntigravityAdapter::new()
            .parse_source_with_steps_deadline(&source, &mut sink, source.end)
            .unwrap_err(),
    );
    assert_eq!(source.delayed.load(std::sync::atomic::Ordering::Relaxed), 1);
    assert!(sink.messages.is_empty());
    assert_eq!(bytes, before);
}

struct DelayedFinalSink {
    end: std::time::Instant,
    captured: CapturingSink,
}
impl CanonicalEventSink for DelayedFinalSink {
    fn emit_message(
        &mut self,
        event: agent_session_grep_ports::MessageEvent<'_>,
    ) -> PortResult<()> {
        self.captured.emit_message(event)?;
        wait_past(self.end);
        Ok(())
    }
}
#[test]
fn final_jsonl_emission_returning_after_original_deadline_is_error_not_complete_success() {
    let bytes = transcript(&[json_step(0, "MODEL", "synthetic last message")]);
    let before = bytes.clone();
    let mut sink = DelayedFinalSink {
        end: future_deadline(),
        captured: CapturingSink::default(),
    };
    let end = sink.end;
    assert_deadline(
        AntigravityAdapter::new()
            .parse_source_with_steps_deadline(&SliceSource::new(&bytes), &mut sink, end)
            .unwrap_err(),
    );
    assert_eq!(sink.captured.messages.len(), 1);
    assert_eq!(bytes, before);
}
#[test]
fn final_sqlite_emission_returning_after_original_deadline_is_error_not_complete_success() {
    let db = database();
    add(&db, 0, 14, 3, &user("synthetic last DB-only message"));
    let bytes = image(&db);
    let before = bytes.clone();
    let mut sink = DelayedFinalSink {
        end: future_deadline(),
        captured: CapturingSink::default(),
    };
    let end = sink.end;
    assert_deadline(
        AntigravityAdapter::new()
            .parse_source_with_steps_deadline(&SliceSource::new(&bytes), &mut sink, end)
            .unwrap_err(),
    );
    assert_eq!(sink.captured.messages.len(), 1);
    assert_eq!(bytes, before);
}
#[test]
fn final_protobuf_step_emission_returning_after_original_deadline_is_error_not_complete_success() {
    let bytes = planner(
        "synthetic last stored Step",
        "synthetic-native-last-message",
    );
    let before = bytes.clone();
    let mut sink = DelayedFinalSink {
        end: future_deadline(),
        captured: CapturingSink::default(),
    };
    let end = sink.end;
    assert_deadline(
        AntigravityAdapter::new()
            .parse_protobuf_step_deadline(&bytes, 7, &mut sink, end)
            .unwrap_err(),
    );
    assert_eq!(sink.captured.messages.len(), 1);
    assert_eq!(bytes, before);
}

#[test]
fn original_deadline_path_preserves_legacy_observation_and_manifest_per_variant() {
    let db = database();
    add(&db, 0, 14, 3, &user("synthetic DB-only request"));
    add(
        &db,
        1,
        15,
        3,
        &planner("synthetic exact response", "synthetic-source-message"),
    );
    for bytes in [
        image(&db),
        transcript(&[json_step(0, "USER_EXPLICIT", "synthetic JSONL request")]),
    ] {
        let legacy = AntigravityAdapter::new()
            .parse_with_steps(&bytes, &mut CapturingSink::default())
            .unwrap();
        let current = AntigravityAdapter::new()
            .parse_source_with_steps_deadline(
                &SliceSource::new(&bytes),
                &mut CapturingSink::default(),
                future_deadline(),
            )
            .unwrap();
        assert_eq!(current, legacy);
        assert!(current.complete && current.report.skipped == 0);
    }
    let manifest = AntigravityAdapter::new().manifest();
    assert_eq!(
        manifest.streaming_support,
        agent_session_grep_ports::StreamingSupport::RecordStream
    );
    assert!(manifest.max_source_size.is_none());
    assert_eq!(
        manifest.max_record_size,
        Some(agent_session_grep_ports::STREAM_RECORD_MAX_BYTES)
    );
}
#[test]
fn original_deadline_path_does_not_hide_late_corruption_or_truncation() {
    let db = database();
    add(&db, 0, 14, 3, &user("synthetic valid prefix"));
    add(&db, 1, 15, 3, &[8, 128]);
    let mut sink = CapturingSink::default();
    let error = AntigravityAdapter::new()
        .parse_source_with_steps_deadline(
            &SliceSource::new(&image(&db)),
            &mut sink,
            future_deadline(),
        )
        .unwrap_err();
    assert!(matches!(error, ProviderError::StructuralFatal(_)));
    assert_ne!(
        error,
        ProviderError::StructuralFatal("Antigravity deadline exceeded".into())
    );
    assert!(sink.messages.is_empty());
    let mut bad = json_step(0, "MODEL", "synthetic shortened body");
    bad["truncated_fields"] = json!(["content"]);
    let bytes = transcript(&[bad]);
    let current = AntigravityAdapter::new()
        .parse_source_with_steps_deadline(&SliceSource::new(&bytes), &mut sink, future_deadline())
        .unwrap();
    assert!(!current.complete);
    assert_eq!(current.report.skipped, 1);
    assert!(sink.messages.is_empty());
}

#[test]
fn original_deadline_path_rejects_short_sqlite_read_and_size_limit_before_publication() {
    struct ShortSnapshot(Vec<u8>);
    impl ReadOnlySource for ShortSnapshot {
        fn len(&self) -> u64 {
            self.0.len() as u64 + 1
        }
        fn open(&self) -> PortResult<Box<dyn BufRead + Send + '_>> {
            Ok(Box::new(Cursor::new(&self.0)))
        }
    }
    let mut sink = CapturingSink::default();
    let error = AntigravityAdapter::new()
        .parse_source_with_steps_deadline(
            &ShortSnapshot(image(&database())),
            &mut sink,
            future_deadline(),
        )
        .unwrap_err();
    assert!(matches!(error, ProviderError::SourceChangedDuringRead(_)));
    assert!(sink.messages.is_empty());
    let error = AntigravityAdapter::new()
        .parse_source_with_steps_deadline(&OversizedSnapshot, &mut sink, future_deadline())
        .unwrap_err();
    assert!(matches!(error, ProviderError::SourceTooLarge { .. }));
    assert!(sink.messages.is_empty());
}
