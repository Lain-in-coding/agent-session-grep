//! Synthetic source/parser contracts, compiled with the owned module.
use super::*;

use agent_session_grep_ports::{ReadOnlySource, SliceSource};

use serde_json::{Value, json};
use std::time::{Duration, Instant};

fn end() -> Instant {
    Instant::now() + Duration::from_secs(10)
}
fn rows(rows: &[Value]) -> Vec<u8> {
    rows.iter()
        .map(|row| format!("{row}\n"))
        .collect::<String>()
        .into_bytes()
}
fn ag_step(index: u64, role: &str, text: &str) -> Value {
    json!({"step_index":index,"type":"GENERIC","source":role,"status":"DONE","content":text})
}

#[test]
fn ag_zero_skips_with_step_gap_keeps_same_parse_incomplete_proof() {
    let bytes = rows(&[ag_step(1, "USER_EXPLICIT", "synthetic original 中文")]);
    let source = SliceSource::new(&bytes);
    let parsed = stage("antigravity", &source, end()).unwrap();
    assert_eq!(parsed.staged.report.skipped, 0);
    assert_eq!(parsed.staged.messages[0].text, "synthetic original 中文");
    assert!(!parsed.completeness.is_complete());
    assert_eq!(
        parsed.completeness.incomplete_reason(),
        Some(IncompleteReason::NativeObservationIncomplete)
    );
    assert_eq!(parsed.completeness.format(), SourceFormat::Jsonl);
    assert_eq!(parsed.completeness.source_bytes(), source.len());
    let native = parsed.completeness.antigravity().unwrap();
    assert!(!native.complete);
    assert_eq!(native.report, parsed.staged.report);
    assert_eq!(native.steps[0].seq, parsed.staged.messages[0].seq);
    assert_eq!(native.steps[0].step_index, 1);
    assert_eq!(native.steps[0].span, parsed.staged.messages[0].span);
    assert_eq!(
        parsed.variant_id,
        agent_session_grep_provider_antigravity::TRANSCRIPT_VARIANT_ID
    );
    assert_eq!(
        input_limits("zcode").unwrap().max_source_bytes,
        Some(256 * 1024 * 1024)
    );
}

use rusqlite::{Connection, MAIN_DB, params};
use std::{
    io::{BufReader, Cursor, Write},
    sync::atomic::{AtomicUsize, Ordering as AtomicOrdering},
    thread,
};

struct CountSource<'a> {
    bytes: &'a [u8],
    expected: u64,
    opens: AtomicUsize,
    bytes_read: AtomicUsize,
}
impl<'a> CountSource<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            expected: bytes.len() as u64,
            opens: AtomicUsize::new(0),
            bytes_read: AtomicUsize::new(0),
        }
    }
}
impl ReadOnlySource for CountSource<'_> {
    fn len(&self) -> u64 {
        self.expected
    }
    fn open(&self) -> PortResult<Box<dyn BufRead + Send + '_>> {
        self.opens.fetch_add(1, AtomicOrdering::Relaxed);
        Ok(Box::new(CountReader {
            inner: Cursor::new(self.bytes),
            count: &self.bytes_read,
        }))
    }
}
struct CountReader<'a> {
    inner: Cursor<&'a [u8]>,
    count: &'a AtomicUsize,
}
impl Read for CountReader<'_> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let read = self.inner.read(output)?;
        self.count.fetch_add(read, AtomicOrdering::Relaxed);
        Ok(read)
    }
}
impl BufRead for CountReader<'_> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        self.inner.fill_buf()
    }
    fn consume(&mut self, amount: usize) {
        self.inner.consume(amount);
        self.count.fetch_add(amount, AtomicOrdering::Relaxed);
    }
}
#[test]
fn ag_complete_uses_only_header_and_one_full_parse_with_exact_steps_and_spans() {
    let bytes = rows(&[
        ag_step(0, "USER_EXPLICIT", "  synthetic user 中文\n original  "),
        json!({"step_index":1,"type":"CONVERSATION_HISTORY","source":"SYSTEM","status":"DONE"}),
        ag_step(2, "MODEL", "synthetic assistant"),
    ]);
    let before = bytes.clone();
    let source = CountSource::new(&bytes);
    let parsed = stage("antigravity", &source, end()).unwrap();
    assert!(parsed.completeness.is_complete());
    assert_eq!(parsed.staged.messages.len(), 2);
    assert_eq!(source.opens.load(AtomicOrdering::Relaxed), 2);
    assert_eq!(
        source.bytes_read.load(AtomicOrdering::Relaxed),
        bytes.len() + 16
    );
    let proof = parsed.completeness.antigravity().unwrap();
    assert_eq!(proof.report, parsed.staged.report);
    assert_eq!(
        proof
            .steps
            .iter()
            .map(|step| (step.seq, step.step_index))
            .collect::<Vec<_>>(),
        [(0, 0), (1, 2)]
    );
    for (message, step) in parsed.staged.messages.iter().zip(&proof.steps) {
        assert_eq!(step.span, message.span);
        let (start, finish) = step.span.unwrap();
        let original: Value =
            serde_json::from_slice(&bytes[start as usize..finish as usize]).unwrap();
        assert_eq!(original["content"].as_str().unwrap(), message.text);
        assert!(message.native_id.is_empty());
    }
    assert_eq!(bytes, before);
}
#[test]
fn ag_truncated_source_never_becomes_complete_despite_visible_prefix() {
    let mut truncated = ag_step(1, "MODEL", "synthetic shortened result");
    truncated["truncated_fields"] = json!(["content"]);
    let bytes = rows(&[ag_step(0, "USER_EXPLICIT", "synthetic prefix"), truncated]);
    let parsed = stage("antigravity", &SliceSource::new(&bytes), end()).unwrap();
    assert!(!parsed.completeness.is_complete());
    assert_eq!(parsed.staged.report.skipped, 1);
    assert_eq!(parsed.staged.messages.len(), 1);
    assert!(!parsed.completeness.antigravity().unwrap().complete);
}

fn scalar(field: u32, value: u64) -> Vec<u8> {
    let mut result = varint(u64::from(field) << 3);
    result.extend(varint(value));
    result
}
fn varint(mut value: u64) -> Vec<u8> {
    let mut result = Vec::new();
    while value >= 128 {
        result.push((value as u8 & 127) | 128);
        value >>= 7;
    }
    result.push(value as u8);
    result
}
fn field_bytes(field: u32, bytes: &[u8]) -> Vec<u8> {
    let mut result = varint((u64::from(field) << 3) | 2);
    result.extend(varint(bytes.len() as u64));
    result.extend_from_slice(bytes);
    result
}
fn ag_database() -> Connection {
    let db = Connection::open_in_memory().unwrap();
    db.execute_batch("CREATE TABLE trajectory_meta(trajectory_id TEXT PRIMARY KEY,cascade_id TEXT,trajectory_type INTEGER,source INTEGER);
        CREATE TABLE steps(idx INTEGER PRIMARY KEY,step_type INTEGER NOT NULL,status INTEGER NOT NULL,
            has_subtrajectory NUMERIC NOT NULL DEFAULT 0,metadata BLOB,error_details BLOB,permissions BLOB,
            task_details BLOB,render_info BLOB,step_payload BLOB,step_format INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE trajectory_metadata_blob(id TEXT PRIMARY KEY,data BLOB);").unwrap();
    let native = "10000000-0000-4000-8000-000000000001";
    db.execute(
        "INSERT INTO trajectory_meta VALUES(?1,?2,4,17)",
        ["20000000-0000-4000-8000-000000000002", native],
    )
    .unwrap();
    db.execute(
        "INSERT INTO trajectory_metadata_blob VALUES('main',?1)",
        [field_bytes(6, native.as_bytes())],
    )
    .unwrap();
    let mut step = scalar(1, 14);
    step.extend(scalar(4, 3));
    step.extend(field_bytes(
        19,
        &field_bytes(2, "synthetic DB-only 中文".as_bytes()),
    ));
    db.execute(
        "INSERT INTO steps(idx,step_type,status,step_payload) VALUES(0,14,3,?1)",
        [step],
    )
    .unwrap();
    db
}
fn ag_sqlite() -> Vec<u8> {
    ag_database().serialize(MAIN_DB).unwrap().to_vec()
}
#[test]
fn ag_db_only_is_native_sqlite_not_jsonl_and_keeps_stored_session_identity() {
    let bytes = ag_sqlite();
    let source = CountSource::new(&bytes);
    let parsed = stage("antigravity", &source, end()).unwrap();
    assert!(parsed.completeness.is_complete());
    assert_eq!(parsed.completeness.format(), SourceFormat::Sqlite);
    assert_eq!(
        parsed.variant_id,
        agent_session_grep_provider_antigravity::CONVERSATION_VARIANT_ID
    );
    assert_eq!(source.opens.load(AtomicOrdering::Relaxed), 2);
    assert_eq!(
        source.bytes_read.load(AtomicOrdering::Relaxed),
        bytes.len() + 16
    );
    assert_eq!(parsed.staged.messages[0].text, "synthetic DB-only 中文");
    assert!(parsed.staged.messages[0].span.is_none());
    assert_eq!(
        parsed.staged.report.session_native_id.as_deref(),
        Some("10000000-0000-4000-8000-000000000001")
    );
    let proof = parsed.completeness.antigravity().unwrap();
    assert_eq!(proof.report, parsed.staged.report);
    assert_eq!(proof.steps[0].span, None);
}

#[test]
fn ag_contradictory_db_native_identity_and_late_step_scalar_reject_the_whole_batch() {
    let identity = ag_database();
    identity
        .execute(
            "UPDATE trajectory_metadata_blob SET data=?1 WHERE id='main'",
            [field_bytes(6, b"30000000-0000-4000-8000-000000000003")],
        )
        .unwrap();
    let scalar = ag_database();
    let payload: Vec<u8> = scalar
        .query_row("SELECT step_payload FROM steps WHERE idx=0", [], |row| {
            row.get(0)
        })
        .unwrap();
    // Step 0 emits first. A later row claims a status contradicting its payload.
    scalar
        .execute(
            "INSERT INTO steps(idx,step_type,status,step_payload) VALUES(1,14,2,?1)",
            [payload],
        )
        .unwrap();
    for db in [identity, scalar] {
        let bytes = db.serialize(MAIN_DB).unwrap().to_vec();
        let before = bytes.clone();
        let error = stage("antigravity", &SliceSource::new(&bytes), end())
            .unwrap_err()
            .to_string();
        assert!(!error.contains("synthetic"));
        assert!(error.len() < 200);
        assert_eq!(bytes, before);
    }
}

fn zcode_sqlite(unknown_part: bool) -> Vec<u8> {
    let db = Connection::open_in_memory().unwrap();
    db.execute_batch("PRAGMA foreign_keys=ON;
        CREATE TABLE session(id TEXT PRIMARY KEY,project_id TEXT,parent_id TEXT,directory TEXT,version TEXT,time_created INTEGER,time_updated INTEGER,revert TEXT);
        CREATE TABLE message(id TEXT PRIMARY KEY,session_id TEXT NOT NULL REFERENCES session(id),time_created INTEGER,time_updated INTEGER,data TEXT,sequence INTEGER);
        CREATE TABLE part(id TEXT PRIMARY KEY,message_id TEXT NOT NULL REFERENCES message(id),session_id TEXT NOT NULL REFERENCES session(id),time_created INTEGER,time_updated INTEGER,data TEXT,sequence INTEGER);
        CREATE TABLE session_entry(id TEXT PRIMARY KEY,session_id TEXT,kind TEXT,data TEXT);
        INSERT INTO session VALUES('synthetic-parent','synthetic-project',NULL,NULL,'arbitrary-session-version',1000,2000,NULL);
        INSERT INTO session VALUES('synthetic-child','synthetic-project','synthetic-parent',NULL,'different',1000,2000,NULL);").unwrap();
    for (message, session, seq, role) in [
        ("synthetic-m1", "synthetic-parent", 0, "user"),
        ("synthetic-m2", "synthetic-child", 2, "assistant"),
    ] {
        db.execute(
            "INSERT INTO message VALUES(?1,?2,1000,1000,?3,?4)",
            params![message, session, json!({"role":role}).to_string(), seq],
        )
        .unwrap();
    }
    for (part, message, session, seq, payload) in [
        (
            "synthetic-later",
            "synthetic-m1",
            "synthetic-parent",
            8,
            json!({"type":"text","text":"second"}),
        ),
        (
            "synthetic-earlier",
            "synthetic-m1",
            "synthetic-parent",
            2,
            json!({"type":"text","text":"  first 中文  "}),
        ),
        (
            "synthetic-tool",
            "synthetic-m2",
            "synthetic-child",
            3,
            json!({"type":"tool","callID":"synthetic-call","tool":"Read","state":{"status":"completed","input":{"file_path":"synthetic.rs"}}}),
        ),
        (
            "synthetic-child-text",
            "synthetic-m2",
            "synthetic-child",
            1,
            if unknown_part {
                json!({"type":"future-required-part","text":"must not publish"})
            } else {
                json!({"type":"text","text":"synthetic child original"})
            },
        ),
    ] {
        db.execute(
            "INSERT INTO part VALUES(?1,?2,?3,1000,1000,?4,?5)",
            params![part, message, session, payload.to_string(), seq],
        )
        .unwrap();
    }
    db.serialize(MAIN_DB).unwrap().to_vec()
}
#[test]
fn zcode_one_source_read_keeps_ordered_parts_children_activities_and_native_keys() {
    let bytes = zcode_sqlite(false);
    let before = bytes.clone();
    let source = CountSource::new(&bytes);
    let parsed = stage("zcode", &source, end()).unwrap();
    assert!(parsed.completeness.is_complete());
    assert_eq!(parsed.completeness.format(), SourceFormat::Sqlite);
    assert_eq!(
        parsed.variant_id,
        agent_session_grep_provider_zcode::VARIANT_ID
    );
    assert_eq!(
        source.opens.load(AtomicOrdering::Relaxed),
        1,
        "no second whole read/probe"
    );
    assert_eq!(source.bytes_read.load(AtomicOrdering::Relaxed), bytes.len());
    assert_eq!(parsed.staged.messages.len(), 2);
    assert!(parsed.staged.report.session_observation.multi_session);
    let parent = parsed
        .staged
        .messages
        .iter()
        .find(|message| !message.is_sidechain)
        .unwrap();
    let child = parsed
        .staged
        .messages
        .iter()
        .find(|message| message.is_sidechain)
        .unwrap();
    assert_eq!(parent.text, "  first 中文  \nsecond");
    assert_eq!(child.text, "synthetic child original");
    assert!(parent.session.is_some());
    assert_ne!(parent.session, child.session);
    assert!(!parent.native_id.is_empty());
    assert_eq!(parsed.staged.activities.len(), 1);
    assert_eq!(
        parsed.staged.activities[0].message_native_id,
        child.native_id
    );
    assert_eq!(
        parsed.staged.activities[0].activity.status,
        agent_session_grep_domain::ToolActivityStatus::Success
    );
    assert!(
        parsed
            .staged
            .messages
            .iter()
            .all(|message| message.span.is_none())
    );
    assert_eq!(bytes, before);
}
#[test]
fn zcode_unknown_part_preserves_partial_proof_without_replacement_grant() {
    let bytes = zcode_sqlite(true);
    let parsed = stage("zcode", &SliceSource::new(&bytes), end()).unwrap();
    assert_eq!(parsed.staged.report.skipped, 1);
    assert!(!parsed.completeness.is_complete());
    assert_eq!(
        parsed.completeness.incomplete_reason(),
        Some(IncompleteReason::SkippedRecords)
    );
}

fn dsh_header(version: u64) -> Value {
    json!({"type":"session","version":version,"id":"synthetic-session","createdAt":0,"isSeeded":false,"delegationDepth":0})
}
fn dsh_user(seq: u64, text: &str) -> Value {
    json!({"type":"user/message","seq":seq,"time":1_700_000_000_123_u64,"data":{"id":format!("synthetic-{seq}"),"role":"user","content":[{"type":"text","text":text}],"source":{"kind":"user"}},"surfaceOp":"append"})
}
fn frame(bytes: &[u8]) -> Vec<u8> {
    let mut encoder = zstd::stream::write::Encoder::new(Vec::new(), 1).unwrap();
    encoder.include_checksum(true).unwrap();
    encoder.write_all(bytes).unwrap();
    encoder.finish().unwrap()
}
#[test]
fn dsh_concatenated_native_frames_are_not_subject_to_jsonl_health() {
    let mut bytes = frame(&rows(&[dsh_header(4), dsh_user(0, "synthetic first 中文")]));
    bytes.extend(frame(&rows(&[dsh_user(1, "synthetic second")])));
    let before = bytes.clone();
    let parsed = stage("deepseek-harness", &SliceSource::new(&bytes), end()).unwrap();
    assert!(parsed.completeness.is_complete());
    assert_eq!(parsed.completeness.format(), SourceFormat::ZstdJsonl);
    assert_eq!(
        parsed
            .staged
            .messages
            .iter()
            .map(|message| message.text.as_str())
            .collect::<Vec<_>>(),
        ["synthetic first 中文", "synthetic second"]
    );
    assert!(
        parsed
            .staged
            .messages
            .iter()
            .all(|message| message.span.is_none())
    );
    assert_eq!(
        parsed.staged.report.session_native_id.as_deref(),
        Some("synthetic-session")
    );
    assert_eq!(bytes, before);
}
#[test]
fn dsh_torn_last_frame_and_future_format_never_claim_complete() {
    let mut bytes = frame(&rows(&[dsh_header(4), dsh_user(0, "synthetic prefix")]));
    let mut torn = frame(&rows(&[dsh_user(1, "synthetic incomplete tail")]));
    torn.truncate(torn.len() / 2);
    bytes.extend(torn);
    let parsed = stage("deepseek-harness", &SliceSource::new(&bytes), end()).unwrap();
    assert!(!parsed.completeness.is_complete());
    assert!(parsed.staged.report.skipped > 0);
    let future = frame(&rows(&[
        dsh_header(5),
        dsh_user(0, "future must not publish"),
    ]));
    assert!(stage("deepseek-harness", &SliceSource::new(&future), end()).is_err());
}
#[test]
fn dsh_frames_without_checksum_cannot_authorize_complete_observation() {
    fn unchecked_frame(bytes: &[u8]) -> Vec<u8> {
        let mut encoder = zstd::stream::write::Encoder::new(Vec::new(), 1).unwrap();
        encoder.include_checksum(false).unwrap();
        encoder.write_all(bytes).unwrap();
        encoder.finish().unwrap()
    }
    let header = rows(&[dsh_header(4), dsh_user(0, "synthetic checked prefix")]);
    let unchecked = unchecked_frame(&rows(&[dsh_user(1, "synthetic unchecked tail")]));
    assert_eq!(unchecked[4] & 4, 0);
    for bytes in [
        unchecked.clone(),
        [frame(&header), unchecked].concat(),
        unchecked_frame(&header),
        [frame(&header), unchecked_frame(&[])].concat(),
    ] {
        let before = bytes.clone();
        let error = stage("deepseek-harness", &SliceSource::new(&bytes), end())
            .unwrap_err()
            .to_string();
        assert!(!error.contains("synthetic"));
        assert!(error.len() < 200);
        assert_eq!(bytes, before);
    }
}
#[test]
fn dsh_missing_final_checksum_bytes_never_authorize_staged_tail() {
    for missing in 1..=4 {
        let mut bytes = frame(&rows(&[dsh_header(4), dsh_user(0, "synthetic prefix")]));
        let mut tail = frame(&rows(&[dsh_user(1, "synthetic decoded tail")]));
        tail.truncate(tail.len() - missing);
        bytes.extend(tail);
        let before = bytes.clone();
        let parsed = stage("deepseek-harness", &SliceSource::new(&bytes), end()).unwrap();
        assert!(!parsed.completeness.is_complete());
        assert!(parsed.staged.report.skipped > 0);
        assert_eq!(bytes, before);
    }
}
#[test]
fn dsh_skippable_metadata_and_trailing_frame_prefix_cannot_grant_complete() {
    let prefix = frame(&rows(&[dsh_header(4), dsh_user(0, "synthetic original")]));
    let mut skippable = vec![0x50, 0x2a, 0x4d, 0x18];
    let metadata = b"synthetic custom frame";
    skippable.extend_from_slice(&(metadata.len() as u32).to_le_bytes());
    skippable.extend_from_slice(metadata);
    let bytes = [prefix.clone(), skippable].concat();
    assert!(stage("deepseek-harness", &SliceSource::new(&bytes), end()).is_err());
    for trailing in [&b"\x28"[..], &b"\x28\xb5\x2f"[..]] {
        let bytes = [prefix.as_slice(), trailing].concat();
        let parsed = stage("deepseek-harness", &SliceSource::new(&bytes), end()).unwrap();
        assert!(!parsed.completeness.is_complete());
        assert!(parsed.staged.report.skipped > 0);
    }
}

#[test]
fn dsh_chunked_frame_scan_preserves_exact_native_facts_without_an_extra_read() {
    struct ChunkedSource<'a> {
        bytes: &'a [u8],
        capacity: usize,
        opens: AtomicUsize,
    }
    impl ReadOnlySource for ChunkedSource<'_> {
        fn len(&self) -> u64 {
            self.bytes.len() as u64
        }
        fn open(&self) -> PortResult<Box<dyn BufRead + Send + '_>> {
            self.opens.fetch_add(1, AtomicOrdering::Relaxed);
            Ok(Box::new(BufReader::with_capacity(
                self.capacity,
                Cursor::new(self.bytes),
            )))
        }
    }
    let original = "  synthetic original 中文\r\n body  ";
    let plain = rows(&[dsh_header(4), dsh_user(0, original)]);
    // The split cuts a logical JSONL record, independent of compressed frames.
    let split = plain.len() / 2;
    let mut bytes = frame(&plain[..split]);
    bytes.extend(frame(&[]));
    bytes.extend(frame(&plain[split..]));
    let before = bytes.clone();
    for capacity in [1, 2, 3, 7, READ_CHUNK_BYTES] {
        let source = ChunkedSource {
            bytes: &bytes,
            capacity,
            opens: AtomicUsize::new(0),
        };
        let parsed = stage("deepseek-harness", &source, end()).unwrap();
        assert!(parsed.completeness.is_complete());
        assert_eq!(parsed.staged.report.committed, 1);
        assert_eq!(parsed.staged.report.skipped, 0);
        assert_eq!(parsed.staged.messages[0].text, original);
        assert_eq!(parsed.staged.messages[0].native_id, "synthetic-0");
        assert_eq!(parsed.staged.messages[0].seq, 0);
        assert!(parsed.staged.messages[0].span.is_none());
        assert_eq!(
            parsed.staged.report.session_native_id.as_deref(),
            Some("synthetic-session")
        );
        assert_eq!(source.opens.load(AtomicOrdering::Relaxed), 2);
    }
    assert_eq!(bytes, before);
}

#[test]
fn dsh_known_content_size_and_multiple_blocks_preserve_bounded_native_text() {
    for length in [1, 4_096, 70_000, 300_000] {
        let text = "x".repeat(length);
        let plain = rows(&[dsh_header(4), dsh_user(0, &text)]);
        let mut encoder = zstd::stream::write::Encoder::new(Vec::new(), 1).unwrap();
        encoder.include_checksum(true).unwrap();
        encoder.include_contentsize(true).unwrap();
        encoder
            .set_pledged_src_size(Some(plain.len() as u64))
            .unwrap();
        encoder.write_all(&plain).unwrap();
        let bytes = encoder.finish().unwrap();
        let parsed = stage("deepseek-harness", &SliceSource::new(&bytes), end()).unwrap();
        assert!(parsed.completeness.is_complete());
        assert_eq!(parsed.staged.report.committed, 1);
        assert_eq!(parsed.staged.report.skipped, 0);
        assert_eq!(parsed.staged.messages[0].native_id, "synthetic-0");
        assert_eq!(parsed.staged.messages[0].text, text);
    }
}

#[test]
fn dsh_deadline_expiring_at_final_checksum_discards_decoded_prefix() {
    let mut bytes = frame(&rows(&[dsh_header(4), dsh_user(0, "synthetic prefix")]));
    bytes.extend(frame(&rows(&[dsh_user(1, "synthetic decoded tail")])));
    let first_bytes = bytes.len() - 1;
    let original_end = Instant::now() + Duration::from_millis(100);
    let source = DelayedSource {
        bytes,
        deadline: original_end,
        first_bytes,
        opens: AtomicUsize::new(0),
    };
    assert!(matches!(
        stage("deepseek-harness", &source, original_end),
        Err(AppError::Provider(ProviderError::StructuralFatal(reason)))
            if reason == DEADLINE_MESSAGE
    ));
    assert!(Instant::now() >= original_end);
}

#[test]
fn dsh_complete_frame_corruption_discards_prefix_batch() {
    let mut bytes = frame(&rows(&[
        dsh_header(4),
        dsh_user(0, "synthetic valid prefix"),
    ]));
    let mut corrupt = frame(&rows(&[dsh_user(1, "synthetic must not publish")]));
    *corrupt.last_mut().unwrap() ^= 1;
    bytes.extend(corrupt);
    assert!(stage("deepseek-harness", &SliceSource::new(&bytes), end()).is_err());
}

fn claude_rows() -> Vec<Value> {
    vec![
        json!({"type":"user","uuid":"synthetic-user","sessionId":"synthetic-session","timestamp":"2026-01-01T00:00:00Z","message":{"role":"user","content":"synthetic user 中文"}}),
        json!({"type":"assistant","uuid":"synthetic-assistant","parentUuid":"synthetic-user","sessionId":"synthetic-session","timestamp":"2026-01-01T00:00:01Z","message":{"role":"assistant","content":[{"type":"text","text":"synthetic answer"},{"type":"tool_use","id":"synthetic-call","name":"Read","input":{"file_path":"synthetic.rs"}}],"usage":{"input_tokens":7,"output_tokens":3,"cache_read_input_tokens":2,"cache_creation_input_tokens":1}}}),
    ]
}
fn codex_rows() -> Vec<Value> {
    vec![
        json!({"timestamp":"2026-01-01T00:00:00Z","type":"session_meta","payload":{"session_id":"synthetic-codex-session"}}),
        json!({"timestamp":"2026-01-01T00:00:01Z","type":"response_item","payload":{"type":"message","id":"synthetic-codex-message","role":"user","content":[{"type":"input_text","text":"synthetic codex original 中文"}]}}),
        json!({"timestamp":"2026-01-01T00:00:02Z","type":"event_msg","payload":{"type":"token_count","info":{"total_token_usage":{"input_tokens":10,"cached_input_tokens":4,"output_tokens":6,"reasoning_output_tokens":2,"total_tokens":16}}}}),
    ]
}
fn wb_rows() -> Vec<Value> {
    vec![
        json!({"type":"session-meta","id":"synthetic-header","sessionId":"synthetic-wb-session","timestamp":0,"meta":{"codebuddy.ai/hostKind":"workbuddy"}}),
        json!({"type":"message","id":"synthetic-wb-message","sessionId":"synthetic-wb-session","timestamp":1_700_000_000_123_i64,"role":"assistant","content":[{"type":"text","text":"synthetic WorkBuddy original 中文"}],"__codebuddyLocal":{"sensitiveUserInputReviewed":true}}),
        json!({"type":"function_call","callId":"synthetic-call","name":"Read","arguments":{"file_path":"synthetic.rs"},"sessionId":"synthetic-wb-session","messageId":"synthetic-wb-message"}),
        json!({"type":"function_call_result","callId":"synthetic-call","status":"success","sessionId":"synthetic-wb-session","messageId":"synthetic-wb-message"}),
    ]
}
#[test]
fn claude_canonical_parser_preserves_session_parent_usage_and_activity() {
    let bytes = rows(&claude_rows());
    let parsed = stage("claude-code", &SliceSource::new(&bytes), end()).unwrap();
    assert!(parsed.completeness.is_complete());
    assert_eq!(parsed.completeness.format(), SourceFormat::Jsonl);
    assert_eq!(parsed.variant_id, "claude-code/jsonl-v1");
    assert_eq!(parsed.staged.messages.len(), 2);
    assert_eq!(
        parsed.staged.messages[1].parent_native_id.as_deref(),
        Some("synthetic-user")
    );
    assert_eq!(parsed.staged.messages[0].text, "synthetic user 中文");
    assert_eq!(
        parsed.staged.report.session_native_id.as_deref(),
        Some("synthetic-session")
    );
    assert_eq!(parsed.staged.usage_events.len(), 1);
    assert_eq!(parsed.staged.usage_events[0].usage.input_tokens, 7);
    assert_eq!(parsed.staged.activities.len(), 1);
    assert_eq!(
        parsed.staged.activities[0].message_native_id,
        "synthetic-assistant"
    );
}
#[test]
fn codex_canonical_parser_retains_exact_original_session_and_usage() {
    let bytes = rows(&codex_rows());
    let parsed = stage("codex", &SliceSource::new(&bytes), end()).unwrap();
    assert!(parsed.completeness.is_complete());
    assert_eq!(parsed.variant_id, "codex/rollout-jsonl-v1");
    assert_eq!(
        parsed.staged.messages[0].text,
        "synthetic codex original 中文"
    );
    assert_eq!(
        parsed.staged.report.session_native_id.as_deref(),
        Some("synthetic-codex-session")
    );
    assert_eq!(parsed.staged.usage_events.len(), 1);
    // Existing Codex normalization separates cached input from ordinary input.
    assert_eq!(parsed.staged.usage_events[0].usage.input_tokens, 6);
    assert_eq!(parsed.staged.usage_events[0].usage.cache_read_tokens, 4);
    assert_eq!(parsed.staged.usage_events[0].usage.output_tokens, 6);
}
#[test]
fn workbuddy_uses_its_independent_native_parser_and_keeps_anchored_activity() {
    let bytes = rows(&wb_rows());
    let parsed = stage("workbuddy", &SliceSource::new(&bytes), end()).unwrap();
    assert!(parsed.completeness.is_complete());
    assert_eq!(
        parsed.variant_id,
        agent_session_grep_provider_workbuddy::VARIANT_ID
    );
    assert_eq!(
        parsed.staged.messages[0].text,
        "synthetic WorkBuddy original 中文"
    );
    assert_eq!(
        parsed.staged.report.session_native_id.as_deref(),
        Some("synthetic-wb-session")
    );
    assert_eq!(parsed.staged.activities.len(), 1);
    assert_eq!(
        parsed.staged.activities[0].message_native_id,
        "synthetic-wb-message"
    );
    assert_eq!(
        parsed.staged.activities[0].activity.status,
        agent_session_grep_domain::ToolActivityStatus::Success
    );
    assert!(parsed.completeness.antigravity().is_none());
}
#[test]
fn unknown_legacy_top_level_kind_with_zero_skips_still_cannot_grant_complete() {
    for (provider, mut records) in [("claude-code", claude_rows()), ("codex", codex_rows())] {
        records.push(json!({"type":"future-required-record","timestamp":"2026-01-01T00:00:03Z","payload":{"type":"unknown"}}));
        let bytes = rows(&records);
        let parsed = stage(provider, &SliceSource::new(&bytes), end()).unwrap();
        assert_eq!(parsed.staged.report.skipped, 0);
        assert!(!parsed.completeness.is_complete());
        assert_eq!(
            parsed.completeness.incomplete_reason(),
            Some(IncompleteReason::UnsupportedRecord)
        );
    }
}
#[test]
fn malformed_tail_after_probe_sample_is_incomplete_never_healthy_by_zero_skips() {
    let mut records = claude_rows();
    for _ in 0..65 {
        records.push(json!({"type":"summary","summary":"synthetic metadata"}));
    }
    let mut bytes = rows(&records);
    bytes.extend_from_slice(b"{unfinished synthetic tail");
    let parsed = stage("claude-code", &SliceSource::new(&bytes), end()).unwrap();
    assert!(!parsed.completeness.is_complete());
    assert!(parsed.staged.report.skipped > 0);
}

#[test]
fn empty_and_unsupported_sources_never_receive_a_complete_content_grant() {
    let parsed = stage("antigravity", &SliceSource::new(&[]), end()).unwrap();
    assert_eq!(parsed.staged.report.skipped, 0);
    assert!(!parsed.completeness.is_complete());
    for provider in [
        "claude-code",
        "codex",
        "workbuddy",
        "zcode",
        "deepseek-harness",
    ] {
        assert!(stage(provider, &SliceSource::new(&[]), end()).is_err());
    }
    let source = CountSource::new(b"not a valid format");
    assert!(stage("unsupported-synthetic-provider", &source, end()).is_err());
    assert_eq!(source.opens.load(AtomicOrdering::Relaxed), 0);
    assert!(input_limits("unsupported-synthetic-provider").is_err());
    assert!(input_limits("tencent-codebuddy").is_err());
}
#[test]
fn native_input_limits_are_distinct_and_reject_size_before_whole_read() {
    let limits = input_limits("deepseek-harness").unwrap();
    assert_eq!(limits.max_source_bytes, Some(128 * 1024 * 1024));
    assert_eq!(limits.max_decoded_bytes, Some(256 * 1024 * 1024));
    assert_eq!(
        input_limits("antigravity").unwrap().max_sqlite_bytes,
        Some(SQLITE_MAX_SOURCE_BYTES)
    );
    for (provider, max) in [
        ("zcode", MAX_SQLITE_BYTES),
        ("deepseek-harness", MAX_COMPRESSED_BYTES),
    ] {
        let source = CountSource {
            expected: max + 1,
            ..CountSource::new(&[])
        };
        assert!(
            matches!(stage(provider, &source, end()), Err(AppError::Provider(ProviderError::SourceTooLarge { actual, max: supported })) if actual == max + 1 && supported == max)
        );
        assert_eq!(source.opens.load(AtomicOrdering::Relaxed), 0);
    }
    let source = CountSource {
        expected: SQLITE_MAX_SOURCE_BYTES + 1,
        ..CountSource::new(b"SQLite format 3\0")
    };
    assert!(
        matches!(stage("antigravity", &source, end()), Err(AppError::Provider(ProviderError::SourceTooLarge { max, .. })) if max == SQLITE_MAX_SOURCE_BYTES)
    );
    assert_eq!(
        source.opens.load(AtomicOrdering::Relaxed),
        1,
        "only bounded header detection"
    );
}
#[test]
fn short_and_growing_captured_ranges_discard_staging_and_redact_details() {
    let bytes = rows(&claude_rows());
    for expected in [bytes.len() as u64 - 1, bytes.len() as u64 + 1] {
        let source = CountSource {
            expected,
            ..CountSource::new(&bytes)
        };
        assert!(stage("claude-code", &source, end()).is_err());
    }
    struct FailingSource;
    impl ReadOnlySource for FailingSource {
        fn len(&self) -> u64 {
            32
        }
        fn open(&self) -> PortResult<Box<dyn BufRead + Send + '_>> {
            Err(PortError::SourceIo("synthetic-secret-path-and-body".into()))
        }
    }
    let error = stage("antigravity", &FailingSource, end())
        .unwrap_err()
        .to_string();
    assert!(!error.contains("synthetic-secret"));
    assert!(error.len() < 200);
}
#[test]
fn expired_original_deadline_returns_before_source_open_for_every_provider() {
    let deadline = Instant::now() - Duration::from_secs(1);
    for provider in [
        "claude-code",
        "codex",
        "workbuddy",
        "antigravity",
        "zcode",
        "deepseek-harness",
    ] {
        let source = CountSource::new(b"synthetic expired source");
        assert!(
            matches!(stage(provider, &source, deadline), Err(AppError::Provider(ProviderError::StructuralFatal(reason))) if reason == DEADLINE_MESSAGE)
        );
        assert_eq!(source.opens.load(AtomicOrdering::Relaxed), 0);
    }
}

/// First chunk is available immediately; later native reads return only after
/// the original deadline. No arbitrary slow host/source is actually cancelled.
struct DelayedSource {
    bytes: Vec<u8>,
    deadline: Instant,
    first_bytes: usize,
    opens: AtomicUsize,
}
impl ReadOnlySource for DelayedSource {
    fn len(&self) -> u64 {
        self.bytes.len() as u64
    }
    fn open(&self) -> PortResult<Box<dyn BufRead + Send + '_>> {
        self.opens.fetch_add(1, AtomicOrdering::Relaxed);
        Ok(Box::new(BufReader::with_capacity(
            self.first_bytes.max(1),
            DelayedRead {
                source: self,
                offset: 0,
            },
        )))
    }
}
struct DelayedRead<'a> {
    source: &'a DelayedSource,
    offset: usize,
}
impl Read for DelayedRead<'_> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if self.offset >= self.source.first_bytes {
            thread::sleep(
                self.source
                    .deadline
                    .saturating_duration_since(Instant::now())
                    + Duration::from_millis(1),
            );
        }
        let remaining = &self.source.bytes[self.offset..];
        let count = remaining
            .len()
            .min(output.len())
            .min(self.source.first_bytes.max(1));
        output[..count].copy_from_slice(&remaining[..count]);
        self.offset += count;
        Ok(count)
    }
}
#[test]
fn deadline_expiring_inside_native_read_cannot_return_any_staged_batch() {
    let bytes = rows(&[
        ag_step(0, "USER_EXPLICIT", "synthetic original prefix"),
        ag_step(1, "MODEL", "synthetic tail"),
    ]);
    let first_line = bytes.iter().position(|&byte| byte == b'\n').unwrap() + 1;
    let original_end = Instant::now() + Duration::from_millis(100);
    let source = DelayedSource {
        bytes,
        deadline: original_end,
        first_bytes: first_line,
        opens: AtomicUsize::new(0),
    };
    assert!(
        matches!(stage("antigravity", &source, original_end), Err(AppError::Provider(ProviderError::StructuralFatal(reason))) if reason == DEADLINE_MESSAGE)
    );
    assert_eq!(source.opens.load(AtomicOrdering::Relaxed), 2);
    assert!(Instant::now() >= original_end);
}
#[test]
fn wrappers_bound_native_read_and_fill_buf_chunks_without_changing_bytes() {
    let bytes = vec![b'x'; READ_CHUNK_BYTES * 3 + 2];
    let source = CountSource::new(&bytes);
    let guarded = DeadlineSource::new(&source, Deadline(end())).unwrap();
    let mut reader = guarded.open().unwrap();
    let mut large = vec![0; bytes.len()];
    let count = reader.read(&mut large).unwrap();
    assert_eq!(count, READ_CHUNK_BYTES);
    assert_eq!(&large[..count], &bytes[..count]);
    assert_eq!(reader.fill_buf().unwrap().len(), READ_CHUNK_BYTES);
    let mut rest = Vec::new();
    reader.read_to_end(&mut rest).unwrap();
    assert_eq!(rest, bytes[count..]);
    drop(reader);
    assert!(guarded.full_parse_scan.load(Ordering::Relaxed));
    let mut reopened = guarded.open().unwrap();
    assert_eq!(reopened.fill_buf().unwrap()[0], b'x');
    assert_eq!(source.opens.load(AtomicOrdering::Relaxed), 2);
}
#[test]
fn late_source_open_uses_original_deadline_without_default_extension() {
    struct LateOpen {
        deadline: Instant,
    }
    impl ReadOnlySource for LateOpen {
        fn len(&self) -> u64 {
            1
        }
        fn open(&self) -> PortResult<Box<dyn BufRead + Send + '_>> {
            thread::sleep(
                self.deadline.saturating_duration_since(Instant::now()) + Duration::from_millis(1),
            );
            Ok(Box::new(Cursor::new(b"x")))
        }
    }
    let deadline = Instant::now() + Duration::from_millis(30);
    assert!(
        matches!(stage("antigravity", &LateOpen { deadline }, deadline), Err(AppError::Provider(ProviderError::StructuralFatal(reason))) if reason == DEADLINE_MESSAGE)
    );
}
#[test]
fn sink_returning_after_deadline_has_no_success_and_staging_is_discarded() {
    struct LateSink {
        deadline: Instant,
        received: usize,
    }
    impl CanonicalEventSink for LateSink {
        fn emit_message(&mut self, _: MessageEvent<'_>) -> PortResult<()> {
            self.received += 1;
            thread::sleep(
                self.deadline.saturating_duration_since(Instant::now()) + Duration::from_millis(1),
            );
            Ok(())
        }
    }
    let deadline = Instant::now() + Duration::from_millis(30);
    let mut sink = LateSink {
        deadline,
        received: 0,
    };
    let bytes = rows(&[ag_step(0, "USER_EXPLICIT", "synthetic original")]);
    let result = stage_source_with_parser::<()>(&SliceSource::new(&bytes), |input, staged_sink| {
        staged_sink
            .emit_message(MessageEvent {
                session: None,
                seq: 0,
                native_id: "synthetic",
                parent_native_id: None,
                role: "user",
                text: "synthetic prefix discarded",
                timestamp: None,
                is_sidechain: false,
                span: None,
            })
            .unwrap();
        let mut guarded = DeadlineSink {
            inner: &mut sink,
            deadline: Deadline(deadline),
        };
        AntigravityAdapter::new().parse_source_with_steps_deadline(
            input,
            &mut guarded,
            deadline,
        )?;
        Ok((
            ParseReport {
                committed: 1,
                ..Default::default()
            },
            (),
        ))
    });
    assert!(result.is_err());
    assert_eq!(sink.received, 1);
}
#[test]
fn activity_and_usage_sink_deadlines_are_checked_and_errors_redacted() {
    #[derive(Default)]
    struct Sink {
        received: usize,
    }
    impl CanonicalEventSink for Sink {
        fn emit_message(&mut self, _: MessageEvent<'_>) -> PortResult<()> {
            Ok(())
        }
        fn emit_activity(&mut self, _: ToolActivityEvent<'_>) -> PortResult<()> {
            self.received += 1;
            Ok(())
        }
        fn emit_usage(&mut self, _: UsageEvent<'_>) -> PortResult<()> {
            self.received += 1;
            Err(PortError::SourceIo("synthetic-private-usage-detail".into()))
        }
    }
    let mut inner = Sink::default();
    let expired = Deadline(Instant::now() - Duration::from_secs(1));
    let usage = agent_session_grep_domain::UsageObservation {
        input_tokens: 7,
        output_tokens: 3,
        cache_read_tokens: 2,
        cache_write_tokens: 1,
        reasoning_tokens: 0,
        token_source: agent_session_grep_domain::TokenSource::Observed,
    };
    {
        let mut sink = DeadlineSink {
            inner: &mut inner,
            deadline: expired,
        };
        assert!(
            sink.emit_usage(UsageEvent {
                message_native_id: "synthetic",
                usage: usage.clone()
            })
            .is_err()
        );
    }
    assert_eq!(inner.received, 0);
    let mut sink = DeadlineSink {
        inner: &mut inner,
        deadline: Deadline(end()),
    };
    let error = sink
        .emit_usage(UsageEvent {
            message_native_id: "synthetic",
            usage,
        })
        .unwrap_err();
    assert!(!error.to_string().contains("private-usage"));
}

#[test]
fn valid_header_only_sources_are_empty_content_proofs_not_sessions_or_currentness() {
    let codex = rows(&[
        json!({"type":"session_meta","timestamp":"2026-01-01T00:00:00Z","payload":{"session_id":"synthetic-header-only"}}),
    ]);
    let parsed = stage("codex", &SliceSource::new(&codex), end()).unwrap();
    assert!(parsed.completeness.is_complete());
    assert!(parsed.staged.messages.is_empty());
    assert_eq!(parsed.staged.report.committed, 0);
    assert_eq!(parsed.staged.report.skipped, 0);
    let wb = rows(&[wb_rows().remove(0)]);
    let parsed = stage("workbuddy", &SliceSource::new(&wb), end()).unwrap();
    assert!(parsed.completeness.is_complete());
    assert!(parsed.staged.messages.is_empty());
    assert_eq!(parsed.staged.report.skipped, 0);
    let dsh = frame(&rows(&[dsh_header(4)]));
    let parsed = stage("deepseek-harness", &SliceSource::new(&dsh), end()).unwrap();
    assert!(parsed.completeness.is_complete());
    assert!(parsed.staged.messages.is_empty());
    let weak = rows(&[json!({"type":"summary","summary":"synthetic metadata only"})]);
    let parsed = stage("claude-code", &SliceSource::new(&weak), end()).unwrap();
    assert!(!parsed.completeness.is_complete());
    assert_eq!(
        parsed.completeness.incomplete_reason(),
        Some(IncompleteReason::InsufficientFormatEvidence)
    );
}
#[test]
fn future_codex_response_item_without_skips_cannot_authorize_replacement() {
    let mut records = codex_rows();
    records.push(json!({"type":"response_item","timestamp":"2026-01-01T00:00:03Z","payload":{"type":"future-required-response","text":"synthetic unhandled evidence"}}));
    let bytes = rows(&records);
    let parsed = stage("codex", &SliceSource::new(&bytes), end()).unwrap();
    assert_eq!(parsed.staged.report.skipped, 0);
    assert!(!parsed.completeness.is_complete());
    assert_eq!(
        parsed.completeness.incomplete_reason(),
        Some(IncompleteReason::UnsupportedRecord)
    );
}
#[test]
fn legal_final_json_without_newline_and_bom_crlf_keeps_exact_compatibility_spans() {
    let raw = rows(&claude_rows());
    let text = String::from_utf8(raw).unwrap().replace('\n', "\r\n");
    let mut bytes = vec![0xef, 0xbb, 0xbf];
    bytes.extend(text.trim_end_matches("\r\n").as_bytes());
    let parsed = stage("claude-code", &SliceSource::new(&bytes), end()).unwrap();
    assert!(parsed.completeness.is_complete());
    for message in &parsed.staged.messages {
        let (start, finish) = message.span.unwrap();
        let original = &bytes[start as usize..finish as usize];
        let original = original
            .strip_prefix(&[0xef, 0xbb, 0xbf])
            .unwrap_or(original);
        let original: Value = serde_json::from_slice(original).unwrap();
        assert_eq!(original["uuid"].as_str().unwrap(), message.native_id);
    }
}
#[test]
fn late_consume_and_incorrect_bufread_contract_cannot_establish_full_read_proof() {
    struct LateConsume {
        deadline: Instant,
    }
    impl ReadOnlySource for LateConsume {
        fn len(&self) -> u64 {
            1
        }
        fn open(&self) -> PortResult<Box<dyn BufRead + Send + '_>> {
            Ok(Box::new(LateConsumeReader {
                inner: Cursor::new(b"x"),
                deadline: self.deadline,
            }))
        }
    }
    struct LateConsumeReader {
        inner: Cursor<&'static [u8; 1]>,
        deadline: Instant,
    }
    impl Read for LateConsumeReader {
        fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
            self.inner.read(bytes)
        }
    }
    impl BufRead for LateConsumeReader {
        fn fill_buf(&mut self) -> io::Result<&[u8]> {
            self.inner.fill_buf()
        }
        fn consume(&mut self, count: usize) {
            self.inner.consume(count);
            thread::sleep(
                self.deadline.saturating_duration_since(Instant::now()) + Duration::from_millis(1),
            );
        }
    }
    let end = Instant::now() + Duration::from_millis(30);
    let source = LateConsume { deadline: end };
    let guarded = DeadlineSource::new(&source, Deadline(end)).unwrap();
    let mut reader = guarded.open().unwrap();
    assert_eq!(reader.fill_buf().unwrap(), b"x");
    reader.consume(1);
    drop(reader);
    assert!(guarded.failed.load(Ordering::Relaxed));
    assert!(!guarded.full_parse_scan.load(Ordering::Relaxed));
    let source = SliceSource::new(b"x");
    let guarded =
        DeadlineSource::new(&source, Deadline(Instant::now() + Duration::from_secs(5))).unwrap();
    let mut reader = guarded.open().unwrap();
    reader.consume(1); // Not preceded by fill_buf: reject misuse without underflow.
    drop(reader);
    assert!(guarded.failed.load(Ordering::Relaxed));
    assert!(!guarded.full_parse_scan.load(Ordering::Relaxed));
}

#[test]
fn unknown_content_parts_cannot_prove_shortened_legacy_projection_complete() {
    for (provider, mut records) in [
        ("claude-code", claude_rows()),
        ("codex", codex_rows()),
        ("workbuddy", wb_rows()),
    ] {
        let path: &[&str] = match provider {
            "claude-code" => &["message", "content"],
            "codex" => &["payload", "content"],
            _ => &["content"],
        };
        let mut content = &mut records[1];
        for component in path {
            content = &mut content[*component];
        }
        content.as_array_mut().unwrap().push(
            json!({"type":"future-required-block","unhandled_body":"synthetic hidden content"}),
        );
        let bytes = rows(&records);
        let parsed = stage(provider, &SliceSource::new(&bytes), end()).unwrap();
        assert_eq!(
            parsed.staged.report.skipped, 0,
            "existing native compatibility report"
        );
        assert!(!parsed.completeness.is_complete());
        assert_eq!(
            parsed.completeness.incomplete_reason(),
            Some(IncompleteReason::UnsupportedRecord)
        );
    }
}
#[test]
fn supported_native_nontext_parts_are_not_torn_json_and_preserve_original_projection() {
    let mut wb = wb_rows();
    wb[1]["content"]
        .as_array_mut()
        .unwrap()
        .push(json!({"type":"image","data":"synthetic image metadata"}));
    let wb = rows(&wb);
    assert!(
        stage("workbuddy", &SliceSource::new(&wb), end())
            .unwrap()
            .completeness
            .is_complete()
    );
    let mut codex = codex_rows();
    codex[1]["payload"]["content"]
        .as_array_mut()
        .unwrap()
        .push(json!({"type":"input_image","image_url":"synthetic:image"}));
    let codex = rows(&codex);
    assert!(
        stage("codex", &SliceSource::new(&codex), end())
            .unwrap()
            .completeness
            .is_complete()
    );
    let mut claude = claude_rows();
    claude[1]["message"]["content"].as_array_mut().unwrap().push(json!({"type":"tool_result","content":[{"type":"text","text":"synthetic exact result"}]}));
    let claude = rows(&claude);
    assert!(
        stage("claude-code", &SliceSource::new(&claude), end())
            .unwrap()
            .completeness
            .is_complete()
    );
}

#[test]
fn codex_supported_native_usage_metadata_preserves_complete_originals_but_unknown_kind_does_not() {
    let meta = json!({"type":"session_meta","payload":{"id":"synthetic-modern","cwd":"/synthetic","cli_version":"0.163.0"}});
    let message = json!({"type":"response_item","payload":{"type":"message","id":"synthetic-modern-message","role":"user","content":[{"type":"input_text","text":"synthetic modern original"}]}});
    let usage = json!({"type":"token_usage_record","payload":{"input_tokens":37,"output_tokens":11,"future_usage":{"counter":3,"content":null}}});
    let bytes = rows(&[meta.clone(), message.clone(), usage]);
    let parsed = stage("codex", &SliceSource::new(&bytes), end()).unwrap();
    assert!(parsed.completeness.is_complete());
    assert_eq!(parsed.staged.report.skipped, 0);
    assert_eq!(parsed.staged.messages.len(), 1);
    assert_eq!(parsed.staged.messages[0].text, "synthetic modern original");
    let unknown = rows(&[
        meta,
        message,
        json!({"type":"unverified_future_record","payload":{"content":"must not authorize replacement"}}),
    ]);
    let parsed = stage("codex", &SliceSource::new(&unknown), end()).unwrap();
    assert!(!parsed.completeness.is_complete());
    assert_eq!(
        parsed.completeness.incomplete_reason(),
        Some(IncompleteReason::UnsupportedRecord)
    );
}
