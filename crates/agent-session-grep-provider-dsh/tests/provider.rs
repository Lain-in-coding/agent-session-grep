//! Fixture revision 1. Every input is built in memory from synthetic values.
//! No profile, real history, provider fixture or production host is opened.

use agent_session_grep_ports::{
    CanonicalEventSink, Confidence, MessageEvent, MetadataResolution, ParseReport, PortError,
    PortResult, ProviderAdapter, ProviderError, ReadOnlySource,
};
use agent_session_grep_provider_dsh::{
    DeepSeekHarnessAdapter, DshLimits, MAX_COMPRESSED_BYTES, MAX_DECOMPRESSED_BYTES, PROVIDER_ID,
    SESSION_FORMAT_VERSION, VARIANT_ID,
};
use agent_session_grep_testkit::golden::CapturingSink;
use serde_json::{Value, json};
use std::{
    io::{self, BufRead, BufReader, Cursor, Read, Write},
    sync::atomic::{AtomicUsize, Ordering},
};

fn header() -> Value {
    json!({"type":"session","version":4,"id":"synthetic-session","createdAt":0,
        "cwd":"/synthetic/project","isSeeded":false,"delegationDepth":0})
}
fn event(seq: u64, kind: &str, data: Value) -> Value {
    json!({"type":kind,"seq":seq,"time":1_700_000_000_123_u64,"data":data})
}
fn user(seq: u64, id: &str, text: &str) -> Value {
    let mut row = event(
        seq,
        "user/message",
        json!({"id":id,"role":"user",
        "content":[{"type":"text","text":text}],"source":{"kind":"user"}}),
    );
    row["surfaceOp"] = json!("append");
    row
}
fn assistant(seq: u64, id: &str, text: &str) -> Value {
    let mut row = event(
        seq,
        "assistant/message",
        json!({"turn":0,"step":0,
        "message":{"id":id,"role":"assistant","content":[{"type":"text","text":text}],
        "source":{"kind":"model","provider":"synthetic-provider","model":"synthetic-model"}},
        "stream":[]}),
    );
    row["surfaceOp"] = json!("append");
    row
}
fn jsonl(rows: &[Value]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for row in rows {
        serde_json::to_writer(&mut bytes, row).unwrap();
        bytes.push(b'\n');
    }
    bytes
}
fn frame(bytes: &[u8]) -> Vec<u8> {
    let mut encoder = zstd::stream::write::Encoder::new(Vec::new(), 1).unwrap();
    encoder.include_checksum(true).unwrap();
    encoder.write_all(bytes).unwrap();
    encoder.finish().unwrap()
}
fn compressed(rows: &[Value]) -> Vec<u8> {
    frame(&jsonl(rows))
}
fn batches(batches: &[Vec<Value>]) -> Vec<u8> {
    batches.iter().flat_map(|rows| compressed(rows)).collect()
}
fn parse(bytes: &[u8]) -> (ParseReport, CapturingSink) {
    let mut sink = CapturingSink::default();
    let report = DeepSeekHarnessAdapter::new()
        .parse(bytes, &mut sink)
        .unwrap();
    (report, sink)
}
fn failure(rows: &[Value]) -> ProviderError {
    DeepSeekHarnessAdapter::new()
        .parse(&compressed(rows), &mut CapturingSink::default())
        .unwrap_err()
}

#[test]
fn twenty_three_concatenated_frames_emit_all_batches_and_keep_native_session_identity() {
    let mut groups = vec![vec![header()]];
    for seq in 0..22 {
        groups.push(vec![if seq % 2 == 0 {
            user(seq, &format!("native-{seq}"), "synthetic prompt")
        } else {
            assistant(seq, &format!("native-{seq}"), "synthetic response")
        }]);
    }
    let bytes = batches(&groups);
    let original = bytes.clone();
    let adapter = DeepSeekHarnessAdapter::new();
    assert_eq!(adapter.provider_id(), PROVIDER_ID);
    assert_eq!(PROVIDER_ID, "deepseek-harness");
    assert_eq!(SESSION_FORMAT_VERSION, 4);
    let probe = adapter.probe(&bytes).unwrap();
    assert_eq!(probe.variant_id, VARIANT_ID);
    assert_eq!(probe.confidence, Confidence::High);
    let (report, sink) = parse(&bytes);
    assert_eq!(report.committed, 22);
    assert_eq!(report.skipped, 0);
    assert_eq!(
        report.session_native_id.as_deref(),
        Some("synthetic-session")
    );
    assert_eq!(
        report.session_observation.provider_session_id,
        MetadataResolution::Resolved("synthetic-session".into())
    );
    assert_eq!(
        report.session_observation.original_working_directory,
        MetadataResolution::Resolved("/synthetic/project".into())
    );
    assert!(report.session_observation.pair_observed);
    for (ordinal, message) in sink.messages.iter().enumerate() {
        assert_eq!(message.seq, ordinal as u32);
        assert_eq!(message.native_id, format!("native-{ordinal}"));
        assert_eq!(
            message.timestamp.as_deref(),
            Some("2023-11-14T22:13:20.123Z")
        );
        assert_eq!(message.span, None);
        assert_eq!(message.parent_native_id, None);
    }
    assert_eq!(bytes, original);
}

#[test]
fn source_form_task_snapshot_metadata_does_not_duplicate_or_replace_recorded_content() {
    let mut snapshot = user(2, "snapshot-id", "  exact snapshot content\n");
    snapshot["data"]["source"] = json!({"kind":"synthetic-context","form":"snapshot",
        "sections":[{"name":"tasks","text":"not an extra message"}]});
    let mut reply = assistant(3, "reply-id", "answer");
    reply["data"]["stream"] = json!([[0, "synthetic raw stream"], [1, "answer"]]);
    reply["data"]["usage"] = json!({"inputTokens":8,"outputTokens":3});
    let input = compressed(&[
        header(),
        event(
            0,
            "team/task",
            json!({"version":1,"teamId":"synthetic-team","task":{
            "id":"synthetic-task","subject":"task title","description":"not a message",
            "status":"pending","revision":0,"blockedBy":[],"writeScopes":[]}}),
        ),
        event(1, "session/title", json!({"title":"not conversation"})),
        snapshot,
        reply,
        event(
            4,
            "assistant/attempt",
            json!({"turn":0,"step":0,"stream":[[0,"not a message"]]}),
        ),
        event(5, "request/header", json!({"header":{},"reason":"initial"})),
        event(
            6,
            "workspace/changes",
            json!({"synthetic":"not conversation"}),
        ),
    ]);
    let (report, sink) = parse(&input);
    assert_eq!(report.committed, 2);
    assert_eq!(report.skipped, 0);
    assert_eq!(sink.messages[0].text, "  exact snapshot content\n");
    assert_eq!(sink.messages[1].text, "answer");
    assert!(sink.activities.is_empty());
    assert!(sink.usages.is_empty());
}

#[test]
fn whitespace_unicode_long_message_ids_and_nontext_only_records_remain_honest() {
    let id = format!("{}distinct-tail", "same-native-prefix-".repeat(2048));
    let mut row = assistant(0, &id, "");
    row["data"]["message"]["content"] = json!([
        {"type":"text","text":"  中文\t\n"},
        {"type":"reasoning","text":"not visible prose"},
        {"type":"text","text":""},
        {"type":"text","text":" second  \r\n"},
    ]);
    let mut tool_only = assistant(1, "tool-only", "");
    tool_only["data"]["message"]["content"] = json!([
        {"type":"tool-call","id":"call","name":"synthetic-tool","arguments":"{}"}
    ]);
    let (report, sink) = parse(&compressed(&[header(), row, tool_only]));
    assert_eq!(report.committed, 2);
    assert_eq!(sink.messages[0].native_id, id);
    assert_eq!(sink.messages[0].text, "  中文\t\n\n\n second  \r\n");
    assert_eq!(sink.messages[1].native_id, "tool-only");
    assert_eq!(sink.messages[1].text, "");
}

#[test]
fn versions_and_other_provider_headers_are_refused_before_emission() {
    for version in [0, 1, 3, 5, 99] {
        let mut h = header();
        h["version"] = json!(version);
        let error = failure(&[h, user(0, "native", "body")]);
        assert!(matches!(error, ProviderError::AmbiguousVariant(_)));
        assert!(
            error
                .to_string()
                .contains("unsupported DSH session format version")
        );
    }
    for row in [
        json!({"type":"session","version":3,"id":"pi","timestamp":"2026-01-01T00:00:00Z","cwd":"/synthetic"}),
        json!({"type":"session_meta","payload":{"id":"codex"}}),
        json!({"type":"session-meta","sessionId":"workbuddy"}),
    ] {
        assert!(matches!(
            failure(&[row]),
            ProviderError::AmbiguousVariant(_)
        ));
    }
    assert_eq!(
        DeepSeekHarnessAdapter::new()
            .probe(&jsonl(&[header()]))
            .unwrap()
            .confidence,
        Confidence::Ambiguous
    );
}

#[test]
fn unknown_required_records_refuse_but_explicit_ignorable_records_preserve_contiguous_log() {
    for marker in [None, Some(json!(false)), Some(json!(null)), Some(json!(1))] {
        let mut future = event(
            1,
            "future/required",
            json!({"sensitive":"synthetic-private"}),
        );
        if let Some(marker) = marker {
            future["ignorable"] = marker;
        }
        assert!(
            DeepSeekHarnessAdapter::new()
                .parse(
                    &compressed(&[header(), user(0, "first", "body"), future]),
                    &mut CapturingSink::default()
                )
                .is_err()
        );
    }
    let mut future = event(1, "future/optional", json!(["opaque", 27, null]));
    future["ignorable"] = json!(true);
    future["futureField"] = json!({"type":"session","version":99});
    let (report, sink) = parse(&compressed(&[
        header(),
        user(0, "first", "body"),
        future,
        assistant(2, "last", "response"),
    ]));
    assert_eq!(report.committed, 2);
    assert_eq!(report.skipped, 0);
    assert_eq!(sink.messages[1].native_id, "last");
    assert!(
        report
            .diagnostics
            .iter()
            .any(|value| value.contains("ignorable"))
    );
    assert!(!report.diagnostics.join("\n").contains("synthetic-private"));
}

#[test]
fn extra_fields_do_not_break_known_message_roles_or_identities() {
    let mut h = header();
    h["futureMetadata"] = json!({"value":42});
    let mut row = user(0, "native", "body");
    row["futureEnvelope"] = json!(true);
    row["data"]["futurePayload"] = json!({"value":42});
    row["data"]["source"] = json!({"kind":"future-user-attribution","form":"notice",
        "summary":"synthetic summary","future":true});
    let (report, sink) = parse(&compressed(&[h, row]));
    assert_eq!(report.committed, 1);
    assert_eq!(report.skipped, 0);
    assert_eq!(sink.messages[0].native_id, "native");
    assert_eq!(sink.messages[0].text, "body");
}

#[test]
fn sequence_gaps_duplicates_invalid_required_fields_and_multiple_sessions_are_structural_errors() {
    for seq in [1, 9, u64::MAX] {
        assert!(matches!(
            failure(&[header(), user(seq, "native", "body")]),
            ProviderError::StructuralFatal(_)
        ));
    }
    assert!(matches!(
        failure(&[header(), user(0, "one", "body"), user(0, "two", "body")]),
        ProviderError::StructuralFatal(_)
    ));
    assert!(matches!(
        failure(&[header(), user(0, "one", "body"), header()]),
        ProviderError::StructuralFatal(_)
    ));
    for field in ["id", "role", "content", "source"] {
        let mut row = user(0, "native", "body");
        row["data"].as_object_mut().unwrap().remove(field);
        assert!(matches!(
            failure(&[header(), row]),
            ProviderError::StructuralFatal(_)
        ));
    }
    let mut row = assistant(0, "native", "body");
    row["data"]["message"]["id"] = json!(77);
    assert!(matches!(
        failure(&[header(), row]),
        ProviderError::StructuralFatal(_)
    ));
    let mut row = assistant(0, "native", "body");
    row["data"].as_object_mut().unwrap().remove("stream");
    assert!(matches!(
        failure(&[header(), row]),
        ProviderError::StructuralFatal(_)
    ));
}

#[test]
fn safe_integer_utc_time_is_exact_and_invalid_time_never_becomes_unknown_success() {
    for (value, expected) in [
        (0_u64, "1970-01-01T00:00:00.000Z"),
        (999, "1970-01-01T00:00:00.999Z"),
        (1_700_000_000_123, "2023-11-14T22:13:20.123Z"),
        (253_402_300_799_999, "9999-12-31T23:59:59.999Z"),
    ] {
        let mut row = user(0, "native", "body");
        row["time"] = json!(value);
        assert_eq!(
            parse(&compressed(&[header(), row])).1.messages[0]
                .timestamp
                .as_deref(),
            Some(expected)
        );
    }
    for value in [
        json!(-1),
        json!(1.5),
        json!("1700000000123"),
        json!(null),
        json!(253_402_300_800_000_u64),
        json!(u64::MAX),
    ] {
        let mut row = user(0, "native", "body");
        row["time"] = value;
        assert!(matches!(
            failure(&[header(), row]),
            ProviderError::StructuralFatal(_)
        ));
    }
}

#[test]
fn surface_replacements_keep_historical_originals_and_do_not_expand_large_source_ranges() {
    let mut replacement = user(3, "summary", "historical replacement");
    replacement["surfaceOp"] = json!({"op":"replace","startSeq":0,"endSeq":2});
    replacement["sourceEventSeqs"] = json!([[0, 2]]);
    let (report, sink) = parse(&compressed(&[
        header(),
        user(0, "first", "original"),
        assistant(1, "second", "response"),
        user(2, "third", "followup"),
        replacement,
    ]));
    assert_eq!(report.committed, 4);
    assert_eq!(report.skipped, 0);
    assert_eq!(sink.messages[0].text, "original");
    assert_eq!(sink.messages[3].text, "historical replacement");
    assert!(
        report
            .diagnostics
            .iter()
            .any(|value| value.contains("historical evidence"))
    );
    for op in [
        json!(null),
        json!("future"),
        json!({"op":"replace","startSeq":1,"endSeq":0}),
        json!({"op":"replace","startSeq":0,"endSeq":1}),
    ] {
        let mut row = user(1, "native", "body");
        row["surfaceOp"] = op;
        assert!(matches!(
            failure(&[header(), user(0, "first", "body"), row]),
            ProviderError::StructuralFatal(_)
        ));
    }
    let mut row = assistant(0, "native", "body");
    row["sourceEventSeqs"] = json!([0]);
    assert!(matches!(
        failure(&[header(), row]),
        ProviderError::StructuralFatal(_)
    ));
    let mut projection = event(0, "image/offload", json!({"version":1}));
    projection["ignorable"] = json!(true);
    assert!(matches!(
        failure(&[header(), projection]),
        ProviderError::AmbiguousVariant(_)
    ));
}

#[test]
fn subagent_header_marks_messages_without_fabricating_parent_message_edges() {
    let mut h = header();
    h["delegationDepth"] = json!(2);
    h["origin"] = json!("subagent");
    h["parentSession"] = json!("synthetic-parent");
    let (report, sink) = parse(&compressed(&[h, user(0, "native", "body")]));
    assert_eq!(
        report.session_native_id.as_deref(),
        Some("synthetic-session")
    );
    assert!(sink.messages[0].is_sidechain);
    assert_eq!(sink.messages[0].parent_native_id, None);
    let mut h = header();
    h.as_object_mut().unwrap().remove("cwd");
    assert!(
        !parse(&compressed(&[h, user(0, "native", "body")]))
            .0
            .session_observation
            .pair_observed
    );
}

#[test]
fn torn_final_frame_recovers_only_complete_lines_and_remains_explicitly_incomplete() {
    let prefix = compressed(&[header(), user(0, "prefix", "stable")]);
    let tail = compressed(&[
        assistant(1, "tail-one", "response"),
        user(2, "tail-two", "next"),
    ]);
    let mut truncated = prefix.clone();
    truncated.extend(&tail[..tail.len() - 1]);
    let original = truncated.clone();
    let (report, sink) = parse(&truncated);
    // Removing only a checksum byte leaves both complete decoded rows. They
    // are recovered, while the missing frame footer still marks incomplete.
    assert_eq!(report.committed, 3);
    assert_eq!(sink.messages[1].native_id, "tail-one");
    assert_eq!(sink.messages[2].native_id, "tail-two");
    assert_eq!(report.skipped, 1);
    assert_eq!(sink.messages[0].native_id, "prefix");
    assert!(
        report
            .diagnostics
            .iter()
            .any(|value| value.contains("torn final zstd frame"))
    );
    assert_eq!(truncated, original);
    let mut fragment = prefix.clone();
    fragment.extend(&tail[..3]);
    let (report, sink) = parse(&fragment);
    assert_eq!(report.committed, 1);
    assert_eq!(report.skipped, 1);
    assert_eq!(sink.messages.len(), 1);
    let mut unterminated = jsonl(&[assistant(1, "not-complete", "fragment")]);
    unterminated.pop();
    let mut part = frame(&unterminated);
    part.pop();
    let mut input = prefix.clone();
    input.extend(part);
    let (report, sink) = parse(&input);
    assert_eq!(report.committed, 1);
    assert_eq!(report.skipped, 1);
    assert_eq!(sink.messages.len(), 1);
    let mut restored = prefix;
    restored.extend(tail);
    assert_eq!(parse(&restored).0.committed, 3);
    assert_eq!(parse(&restored).0.skipped, 0);
}

#[test]
fn checksummed_corrupt_frame_or_trailing_garbage_is_error_not_recovery() {
    let prefix = compressed(&[header(), user(0, "stable", "body")]);
    let mut corrupt = compressed(&[assistant(1, "bad", "body")]);
    let end = corrupt.len() - 1;
    corrupt[end] ^= 0x40;
    let mut input = prefix.clone();
    input.extend(corrupt);
    assert!(matches!(
        DeepSeekHarnessAdapter::new().parse(&input, &mut CapturingSink::default()),
        Err(ProviderError::StructuralFatal(_))
    ));
    for suffix in [b"garbage".as_slice(), b"\0\0\0\0".as_slice()] {
        let mut input = prefix.clone();
        input.extend(suffix);
        assert!(matches!(
            DeepSeekHarnessAdapter::new().parse(&input, &mut CapturingSink::default()),
            Err(ProviderError::StructuralFatal(_))
        ));
    }
    let mut bad = jsonl(&[header()]);
    bad.extend(b"{invalid complete JSON}\n");
    assert!(matches!(
        DeepSeekHarnessAdapter::new().parse(&frame(&bad), &mut CapturingSink::default()),
        Err(ProviderError::StructuralFatal(_))
    ));
    let mut complete = jsonl(&[header(), user(0, "native", "body")]);
    complete.pop();
    assert!(matches!(
        DeepSeekHarnessAdapter::new().parse(&frame(&complete), &mut CapturingSink::default()),
        Err(ProviderError::StructuralFatal(_))
    ));
}

#[test]
fn one_logical_record_split_across_frames_and_crlf_bom_remains_one_message() {
    let mut plain = b"\xEF\xBB\xBF".to_vec();
    plain.extend(jsonl(&[header(), user(0, "native", "  body\r\n")]));
    let text = String::from_utf8(plain).unwrap().replace('\n', "\r\n");
    let split = text.len() / 2;
    let mut input = frame(&text.as_bytes()[..split]);
    input.extend(frame(&text.as_bytes()[split..]));
    let (report, sink) = parse(&input);
    assert_eq!(report.committed, 1);
    assert_eq!(sink.messages[0].native_id, "native");
    assert_eq!(sink.messages[0].text, "  body\r\n");
    assert_eq!(sink.messages[0].span, None);
}

struct Source {
    bytes: Vec<u8>,
    expected: u64,
    opens: AtomicUsize,
}
impl ReadOnlySource for Source {
    fn len(&self) -> u64 {
        self.expected
    }
    fn open(&self) -> PortResult<Box<dyn BufRead + Send + '_>> {
        self.opens.fetch_add(1, Ordering::Relaxed);
        Ok(Box::new(BufReader::with_capacity(
            7,
            Cursor::new(&self.bytes),
        )))
    }
}
#[test]
fn parse_source_streams_one_capture_and_short_capture_is_not_torn_tail() {
    let bytes = batches(&[
        vec![header()],
        vec![user(0, "native", "body")],
        vec![assistant(1, "reply", "answer")],
    ]);
    let source = Source {
        expected: bytes.len() as u64,
        bytes,
        opens: AtomicUsize::new(0),
    };
    let adapter = DeepSeekHarnessAdapter::new();
    let mut sink = CapturingSink::default();
    let report = adapter.parse_source(&source, &mut sink).unwrap();
    assert_eq!(report.committed, 2);
    assert_eq!(source.opens.load(Ordering::Relaxed), 1);
    assert_eq!(
        adapter.probe_source(&source).unwrap().confidence,
        Confidence::High
    );
    assert_eq!(source.opens.load(Ordering::Relaxed), 2);
    let short = Source {
        expected: source.expected + 1,
        bytes: source.bytes.clone(),
        opens: AtomicUsize::new(0),
    };
    assert!(matches!(
        adapter.parse_source(&short, &mut CapturingSink::default()),
        Err(ProviderError::Io(_))
    ));
}

#[test]
fn input_record_decoded_total_and_decoder_window_limits_are_enforced() {
    let input = compressed(&[header(), user(0, "native", "x".repeat(4096).as_str())]);
    let adapter = DeepSeekHarnessAdapter::with_limits(DshLimits {
        compressed_bytes: 1,
        ..DshLimits::default()
    })
    .unwrap();
    assert!(matches!(
        adapter.parse(&input, &mut CapturingSink::default()),
        Err(ProviderError::SourceTooLarge { max: 1, .. })
    ));
    let adapter = DeepSeekHarnessAdapter::with_limits(DshLimits {
        record_bytes: 300,
        ..DshLimits::default()
    })
    .unwrap();
    assert!(matches!(
        adapter.parse(&input, &mut CapturingSink::default()),
        Err(ProviderError::RecordTooLarge { max: 300, .. })
    ));
    let groups: Vec<_> = std::iter::once(vec![header()])
        .chain((0..12).map(|seq| vec![user(seq, "native", "body")]))
        .collect();
    let adapter = DeepSeekHarnessAdapter::with_limits(DshLimits {
        decompressed_bytes: 1000,
        ..DshLimits::default()
    })
    .unwrap();
    assert!(matches!(
        adapter.parse(&batches(&groups), &mut CapturingSink::default()),
        Err(ProviderError::SourceTooLarge { max: 1000, .. })
    ));
    assert!(
        DeepSeekHarnessAdapter::with_limits(DshLimits {
            compressed_bytes: MAX_COMPRESSED_BYTES + 1,
            ..DshLimits::default()
        })
        .is_err()
    );
    assert!(
        DeepSeekHarnessAdapter::with_limits(DshLimits {
            decompressed_bytes: MAX_DECOMPRESSED_BYTES + 1,
            ..DshLimits::default()
        })
        .is_err()
    );
    let mut encoder = zstd::stream::write::Encoder::new(Vec::new(), 1).unwrap();
    encoder.window_log(20).unwrap();
    encoder.include_checksum(true).unwrap();
    encoder
        .write_all(&jsonl(&[header(), user(0, "native", &"a".repeat(4096))]))
        .unwrap();
    let oversized = encoder.finish().unwrap();
    let adapter = DeepSeekHarnessAdapter::with_limits(DshLimits {
        window_log: 10,
        ..DshLimits::default()
    })
    .unwrap();
    assert!(matches!(
        adapter.parse(&oversized, &mut CapturingSink::default()),
        Err(ProviderError::StructuralFatal(_))
    ));
}

struct FailingSink;
impl CanonicalEventSink for FailingSink {
    fn emit_message(&mut self, _event: MessageEvent<'_>) -> PortResult<()> {
        Err(PortError::Backend(
            "synthetic private backend detail".into(),
        ))
    }
}
#[test]
fn stable_errors_and_bounded_diagnostics_never_embed_private_payloads() {
    let error = DeepSeekHarnessAdapter::new()
        .parse(
            &compressed(&[header(), user(0, "native", "body")]),
            &mut FailingSink,
        )
        .unwrap_err();
    assert!(matches!(error, ProviderError::Io(_)));
    assert!(
        !error
            .to_string()
            .contains("synthetic private backend detail")
    );
    let mut rows = vec![header()];
    for seq in 0..100 {
        let mut row = event(
            seq,
            "future/optional",
            json!({"private":"synthetic-private-body"}),
        );
        row["ignorable"] = json!(true);
        rows.push(row);
    }
    let report = parse(&compressed(&rows)).0;
    assert!(report.diagnostics.len() <= 32);
    assert!(
        !report
            .diagnostics
            .join("\n")
            .contains("synthetic-private-body")
    );
    assert_eq!(report.skipped, 0);
}

struct ErrorReader;
impl Read for ErrorReader {
    fn read(&mut self, _output: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::other("synthetic-private-source-error"))
    }
}
impl BufRead for ErrorReader {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        Err(io::Error::other("synthetic-private-source-error"))
    }
    fn consume(&mut self, _count: usize) {}
}
struct ErrorSource;
impl ReadOnlySource for ErrorSource {
    fn len(&self) -> u64 {
        10
    }
    fn open(&self) -> PortResult<Box<dyn BufRead + Send + '_>> {
        Ok(Box::new(ErrorReader))
    }
}
#[test]
fn source_io_failure_has_private_error_boundary_and_cannot_look_like_deleted_or_empty_success() {
    let error = DeepSeekHarnessAdapter::new()
        .parse_source(&ErrorSource, &mut CapturingSink::default())
        .unwrap_err();
    assert!(matches!(error, ProviderError::Io(_)));
    assert!(!error.to_string().contains("synthetic-private-source-error"));
}

#[test]
fn every_tail_truncation_preserves_only_the_same_complete_native_prefix() {
    let prefix = compressed(&[header(), user(0, "prefix", "stable")]);
    let tail = compressed(&[
        assistant(1, "tail-one", "response"),
        user(2, "tail-two", "next"),
    ]);
    for cut in 1..tail.len() {
        let mut input = prefix.clone();
        input.extend(&tail[..cut]);
        let (report, sink) = parse(&input);
        assert_eq!(report.skipped, 1);
        assert!(report.committed >= 1 && report.committed <= 3);
        for (message, expected) in sink.messages.iter().zip(["prefix", "tail-one", "tail-two"]) {
            assert_eq!(message.native_id, expected);
        }
        assert_eq!(report.committed, sink.messages.len());
    }
}

#[test]
fn required_content_alternatives_and_header_field_types_are_not_silently_guessed() {
    let mut row = user(0, "native", "body");
    row["data"]["content"] = json!([{ "type": "future-content", "text": "never assume prose" }]);
    assert!(matches!(
        failure(&[header(), row]),
        ProviderError::AmbiguousVariant(_)
    ));
    for (field, value) in [
        ("id", json!("  ")),
        ("createdAt", json!(-1)),
        ("cwd", json!(null)),
        ("isSeeded", json!("false")),
        ("delegationDepth", json!(-1)),
        ("origin", json!("future-origin")),
    ] {
        let mut h = header();
        h[field] = value;
        assert!(matches!(failure(&[h]), ProviderError::StructuralFatal(_)));
    }
}
