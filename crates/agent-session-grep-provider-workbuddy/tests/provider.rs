//! Fixture revision 1: all records generated from synthetic values in this
//! test module. No source files, private profiles, transcript bodies or upstream
//! fixtures are opened. Reuses the shared all-fields provider test sink.

use agent_session_grep_ports::{
    CanonicalEventSink, Confidence, MessageEvent, MetadataResolution, ParseReport, PortError,
    PortResult, ProviderAdapter, ProviderError, ReadOnlySource, STREAM_RECORD_MAX_BYTES,
};
use agent_session_grep_provider_workbuddy::{PROVIDER_ID, VARIANT_ID, WorkBuddyAdapter};
use agent_session_grep_testkit::golden::CapturingSink;
use serde_json::{Value, json};
use std::{
    io::{BufRead, BufReader, Cursor},
    sync::atomic::{AtomicUsize, Ordering},
};

fn header() -> Value {
    json!({"type":"session-meta","id":"synthetic-header","sessionId":"synthetic-session",
        "timestamp":0,"meta":{"codebuddy.ai/hostKind":"workbuddy"}})
}
fn message(id: &str, role: &str, text: &str) -> Value {
    json!({"type":"message","id":id,"sessionId":"synthetic-session","cwd":"/synthetic/project",
        "timestamp":1_700_000_000_123_i64,"role":role,"content":[{"type":"text","text":text}],
        "__codebuddyLocal":{"sensitiveUserInputReviewed":true}})
}
fn bytes(rows: &[Value]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for row in rows {
        bytes.extend(serde_json::to_vec(row).unwrap());
        bytes.push(b'\n');
    }
    bytes
}
fn parse(bytes: &[u8]) -> (ParseReport, CapturingSink) {
    let mut sink = CapturingSink::default();
    let report = WorkBuddyAdapter::new().parse(bytes, &mut sink).unwrap();
    (report, sink)
}
#[test]
fn probe_has_independent_workbuddy_identity_and_requires_distinct_structural_markers() {
    let adapter = WorkBuddyAdapter::new();
    assert_eq!(adapter.provider_id(), "workbuddy");
    assert_ne!(PROVIDER_ID, "tencent-codebuddy");
    assert_eq!(VARIANT_ID, "workbuddy/project-jsonl-v1");
    let input = bytes(&[header(), message("message", "user", "code")]);
    let before = input.clone();
    let probe = adapter.probe(&input).unwrap();
    assert_eq!(probe.variant_id, VARIANT_ID);
    assert_eq!(probe.confidence, Confidence::Confirmed);
    assert_eq!(input, before);
    let mut unmarked = message("message", "user", "code");
    unmarked.as_object_mut().unwrap().remove("__codebuddyLocal");
    assert_eq!(
        adapter.probe(&bytes(&[unmarked])).unwrap().confidence,
        Confidence::Low
    );
    assert_eq!(
        adapter
            .probe(&bytes(&[message("message", "user", "text")]))
            .unwrap()
            .confidence,
        Confidence::High
    );
    assert_eq!(parse(&input).1.messages[0].text, "code");
}
#[test]
fn probe_negatives_reject_claude_codebuddy_cli_pi_codex_and_empty_input() {
    let rows = [
        json!({"type":"user","uuid":"synthetic","sessionId":"synthetic","timestamp":"2026-01-01T00:00:00Z","message":{"role":"user","content":"text"}}),
        json!({"type":"message","sessionId":"synthetic","timestamp":"2026-01-01T00:00:00Z","role":"user","content":[{"type":"text","text":"text"}]}),
        json!({"type":"message","id":"short","timestamp":0,"message":{"role":"assistant","content":[{"type":"text","text":"pi"}]}}),
        json!({"type":"response_item","timestamp":"2026-01-01T00:00:00Z","payload":{"type":"message","role":"assistant","content":[{"type":"output_text","text":"codex"}]}}),
        json!({"type":"session","id":"synthetic-pi","cwd":"/synthetic/project"}),
    ];
    let adapter = WorkBuddyAdapter::new();
    for row in rows {
        let input = bytes(&[row]);
        assert!(matches!(
            adapter.probe(&input).unwrap().confidence,
            Confidence::Low | Confidence::Ambiguous
        ));
        assert!(matches!(
            adapter.parse(&input, &mut CapturingSink::default()),
            Err(ProviderError::AmbiguousVariant(_))
        ));
    }
    assert_eq!(
        adapter.probe(b" \n").unwrap().confidence,
        Confidence::Ambiguous
    );
    let mixed = bytes(&[
        header(),
        message("message", "user", "workbuddy"),
        json!({"type":"session","id":"pi"}),
    ]);
    assert_eq!(
        adapter.probe(&mixed).unwrap().confidence,
        Confidence::Ambiguous
    );
}
#[test]
fn current_metadata_is_ignored_without_skipped_conversations_or_fake_usage() {
    let mut record = message("first", "user", "  significant  ");
    record["usage"] = json!({"inventedBucket":100});
    let input = bytes(&[
        header(),
        json!({"type":"ai-title","aiTitle":"Synthetic title","sessionId":"synthetic-session","cwd":"/synthetic/project"}),
        json!({"type":"reasoning","content":[],"rawContent":[{"type":"text","text":"not a conversation"}]}),
        json!({"type":"function_call","callId":"unanchored","name":"synthetic-tool","arguments":{}}),
        json!({"type":"function_call_result","callId":"unanchored","status":"success","output":{"type":"text","text":"never a message"}}),
        json!({"type":"file-history-snapshot","messageId":"first","snapshot":{"trackedFileBackups":{"synthetic":"not a conversation"}}}),
        record,
    ]);
    let (report, sink) = parse(&input);
    assert_eq!(report.committed, 1);
    assert_eq!(report.skipped, 0);
    assert_eq!(sink.messages[0].text, "  significant  ");
    assert!(sink.activities.is_empty());
    assert!(sink.usages.is_empty());
    assert_eq!(
        report.session_native_id.as_deref(),
        Some("synthetic-session")
    );
    assert_eq!(
        report.session_observation.provider_session_id,
        MetadataResolution::Resolved("synthetic-session".into())
    );
    assert!(report.session_observation.pair_observed);
}
#[test]
fn original_text_parts_whitespace_unicode_and_long_native_ids_are_preserved() {
    let id = format!("{}distinct-tail", "same-prefix-".repeat(2048));
    let mut row = message(&id, "assistant", "");
    row["content"] = json!([
        {"type":"text","text":"  中\t\n"},
        {"type":"image","data":"synthetic nontext block"},
        {"type":"text","text":""},
        {"type":"text","text":" second  \r\n"},
    ]);
    let (report, sink) = parse(&bytes(&[header(), row]));
    assert_eq!(report.committed, 1);
    assert_eq!(report.skipped, 0);
    assert_eq!(sink.messages[0].native_id, id);
    assert_eq!(sink.messages[0].text, "  中\t\n\n\n second  \r\n");
    assert_eq!(sink.messages[0].parent_native_id, None);
    assert!(!sink.messages[0].is_sidechain);
}
#[test]
fn source_spans_reference_original_bom_crlf_and_unterminated_last_record_bytes() {
    let first = serde_json::to_vec(&header()).unwrap();
    let row = serde_json::to_vec(&message("native", "user", "Unicode 中\n  end ")).unwrap();
    let mut input = b"\xEF\xBB\xBF".to_vec();
    input.extend(&first);
    input.extend(b"\r\n");
    let start = input.len() as u64;
    input.extend(&row);
    let (report, sink) = parse(&input);
    assert_eq!(report.committed, 1);
    assert_eq!(sink.messages[0].span, Some((start, input.len() as u64)));
    let (a, b) = sink.messages[0].span.unwrap();
    assert_eq!(&input[a as usize..b as usize], &row);
}
#[test]
fn epoch_milliseconds_are_utc_exact_with_bounds_negative_instants_and_leap_years() {
    let cases: [(i64, &str); 8] = [
        (0, "1970-01-01T00:00:00.000Z"),
        (1, "1970-01-01T00:00:00.001Z"),
        (-1, "1969-12-31T23:59:59.999Z"),
        (1_700_000_000_123, "2023-11-14T22:13:20.123Z"),
        (951_782_400_000, "2000-02-29T00:00:00.000Z"),
        (-2_208_988_800_000, "1900-01-01T00:00:00.000Z"),
        (-62_167_219_200_000, "0000-01-01T00:00:00.000Z"),
        (253_402_300_799_999, "9999-12-31T23:59:59.999Z"),
    ];
    for (milliseconds, expected) in cases {
        let mut row = message("timestamp", "assistant", "synthetic");
        row["timestamp"] = json!(milliseconds);
        let (report, sink) = parse(&bytes(&[header(), row]));
        assert_eq!(report.skipped, 0);
        assert_eq!(sink.messages[0].timestamp.as_deref(), Some(expected));
    }
    for invalid in [
        json!(i64::MIN),
        json!(i64::MAX),
        json!(u64::MAX),
        json!(-62_167_219_200_001_i64),
        json!(253_402_300_800_000_i64),
        json!(0.5),
        json!("2026-01-01T00:00:00Z"),
    ] {
        let mut row = message("bad-time", "user", "body");
        row["timestamp"] = invalid;
        let (report, sink) = parse(&bytes(&[header(), row]));
        assert_eq!(report.skipped, 1);
        assert!(sink.messages.is_empty());
    }
}
// Independent test inverse: day counting by leap-year totals and month prefix,
// not the parser's 400-year era/civil conversion.
fn inverse_utc(timestamp: &str) -> i64 {
    let year = timestamp[0..4].parse::<i64>().unwrap();
    let month = timestamp[5..7].parse::<usize>().unwrap();
    let day = timestamp[8..10].parse::<i64>().unwrap();
    let leaps = |end: i64| (end + 3) / 4 - (end + 99) / 100 + (end + 399) / 400;
    let mut days = 365 * year + leaps(year) - (365 * 1970 + leaps(1970));
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let lengths = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    days += lengths.iter().take(month - 1).sum::<i64>() + day - 1;
    let hour = timestamp[11..13].parse::<i64>().unwrap();
    let minute = timestamp[14..16].parse::<i64>().unwrap();
    let second = timestamp[17..19].parse::<i64>().unwrap();
    let fraction = timestamp[20..23].parse::<i64>().unwrap();
    days * 86_400_000 + hour * 3_600_000 + minute * 60_000 + second * 1_000 + fraction
}
#[test]
fn deterministic_arbitrary_integer_timestamps_roundtrip_or_skip_without_panicking() {
    let mut seed = 0x12ab34cd_u64;
    for index in 0..192 {
        seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
        let ms = if index % 3 == 0 {
            seed as i64
        } else {
            (seed % 315_569_520_000_000) as i64 - 62_167_219_200_000
        };
        let mut row = message("random-time", "user", "body");
        row["timestamp"] = json!(ms);
        let (report, sink) = parse(&bytes(&[header(), row]));
        if (-62_167_219_200_000..=253_402_300_799_999).contains(&ms) {
            assert_eq!(report.skipped, 0);
            assert_eq!(
                inverse_utc(sink.messages[0].timestamp.as_deref().unwrap()),
                ms
            );
        } else {
            assert_eq!(report.skipped, 1);
            assert!(sink.messages.is_empty());
        }
    }
}
#[test]
fn first_session_split_and_cwd_pair_observation_never_combine_different_records() {
    let mut no_session = message("one", "user", "body");
    no_session.as_object_mut().unwrap().remove("sessionId");
    let (report, _) = parse(&bytes(&[header(), no_session]));
    assert_eq!(
        report.session_observation.original_working_directory,
        MetadataResolution::Missing
    );
    assert!(!report.session_observation.pair_observed);
    let mut other = message("two", "assistant", "other");
    other["sessionId"] = json!("other-session");
    other["cwd"] = json!("/synthetic/other");
    let (report, sink) = parse(&bytes(&[header(), message("one", "user", "body"), other]));
    assert_eq!(sink.messages.len(), 2);
    assert_eq!(
        report.session_native_id.as_deref(),
        Some("synthetic-session")
    );
    assert!(report.session_observation.multi_session);
    assert_eq!(
        report.session_observation.provider_session_id,
        MetadataResolution::Ambiguous
    );
    assert_eq!(
        report.session_observation.original_working_directory,
        MetadataResolution::Ambiguous
    );
    assert!(
        report
            .diagnostics
            .iter()
            .any(|note| note.contains("first-session"))
    );
    let mut changed = message("three", "user", "body");
    changed["cwd"] = json!("/synthetic/changed");
    let (report, _) = parse(&bytes(&[header(), message("one", "user", "body"), changed]));
    assert_eq!(
        report.session_observation.original_working_directory,
        MetadataResolution::Ambiguous
    );
    assert!(!report.session_observation.multi_session);
}
#[test]
fn malformed_conversations_and_torn_tail_are_skipped_with_bounded_private_diagnostics() {
    let mut bad_role = message("synthetic-sensitive-id", "user", "synthetic-sensitive-body");
    bad_role["role"] = json!("future-role");
    let mut bad_content = message("id", "user", "body");
    bad_content["content"] = json!([{"type":"text","text":77}]);
    let mut bad_id = message("id", "user", "body");
    bad_id["id"] = json!(77);
    let mut input = bytes(&[
        header(),
        message("good", "user", "prefix"),
        bad_role,
        bad_content,
        bad_id,
    ]);
    input.extend(b"{\"type\":\"message\",\"content\":");
    let (report, sink) = parse(&input);
    assert_eq!(report.committed, 1);
    assert_eq!(report.skipped, 4);
    assert_eq!(sink.messages[0].text, "prefix");
    let diagnostics = report.diagnostics.join("\n");
    assert!(!diagnostics.contains("synthetic-sensitive"));
    let mut rows = vec![header(), message("good", "user", "prefix")];
    rows.extend((0..100).map(|_| json!({"type":"future-record","private":"synthetic-sensitive"})));
    let (report, _) = parse(&bytes(&rows));
    assert_eq!(report.skipped, 100);
    assert!(report.diagnostics.len() <= 32);
}
#[test]
fn tool_activity_needs_current_native_message_and_exact_call_pair_without_output_word_inference() {
    use agent_session_grep_domain::ToolActivityStatus;
    let rows = [
        header(),
        message("caller", "assistant", "calling a tool"),
        json!({"type":"function_call","callId":"first-call","messageId":"caller","name":"synthetic-tool","arguments":"{\"path\":\"/synthetic/input\"}"}),
        json!({"type":"reasoning","rawContent":[{"type":"text","text":"ignored"}]}),
        json!({"type":"function_call_result","callId":"first-call","output":{"type":"text","text":"Success! operation completed"}}),
        json!({"type":"function_call","callId":"second-call","messageId":"caller","name":"synthetic-tool","arguments":{}}),
        json!({"type":"function_call_result","callId":"second-call","status":"error","output":{"type":"text","text":"looks successful"}}),
        json!({"type":"function_call","callId":"third-call","messageId":"caller","name":"synthetic-tool","arguments":{}}),
        json!({"type":"function_call_result","callId":"third-call","status":"success","output":{"type":"text","text":"looks failed"}}),
        json!({"type":"function_call","callId":"no-result","messageId":"caller","name":"synthetic-tool","arguments":{}}),
        message("next", "user", "next turn"),
        json!({"type":"function_call_result","callId":"no-result","status":"success"}),
    ];
    let (report, sink) = parse(&bytes(&rows));
    assert_eq!(report.skipped, 0);
    assert_eq!(report.committed, 2);
    assert_eq!(sink.activities.len(), 4);
    assert!(
        sink.activities
            .iter()
            .all(|activity| activity.message_native_id == "caller")
    );
    assert_eq!(
        sink.activities[0].activity.status,
        ToolActivityStatus::Unknown
    );
    assert_eq!(
        sink.activities[1].activity.status,
        ToolActivityStatus::Error
    );
    assert_eq!(
        sink.activities[2].activity.status,
        ToolActivityStatus::Success
    );
    assert_eq!(
        sink.activities[3].activity.status,
        ToolActivityStatus::Unknown
    );
    assert!(
        sink.activities
            .iter()
            .all(|activity| activity.activity.target.is_none())
    );
}
#[test]
fn malformed_message_duplicate_calls_and_other_session_results_cannot_borrow_a_previous_anchor() {
    let mut malformed = message("bad-message", "assistant", "body");
    malformed["content"] = json!(null);
    let rows = [
        header(),
        message("old-caller", "assistant", "tool"),
        malformed,
        json!({"type":"function_call","callId":"after-malformed","name":"synthetic-tool"}),
        json!({"type":"function_call_result","callId":"after-malformed","status":"success"}),
        message("new-caller", "assistant", "tool"),
        json!({"type":"function_call","callId":"duplicate","messageId":"new-caller","name":"synthetic-tool"}),
        json!({"type":"function_call","callId":"duplicate","messageId":"new-caller","name":"different-tool"}),
        json!({"type":"function_call_result","callId":"duplicate","status":"success"}),
        json!({"type":"function_call","callId":"other-session-result","messageId":"new-caller","name":"synthetic-tool"}),
        json!({"type":"function_call_result","callId":"other-session-result","status":"success","sessionId":"unrelated"}),
    ];
    let (report, sink) = parse(&bytes(&rows));
    assert_eq!(report.skipped, 1);
    assert_eq!(sink.activities.len(), 1);
    assert_eq!(sink.activities[0].message_native_id, "new-caller");
    assert_eq!(
        sink.activities[0].activity.status,
        agent_session_grep_domain::ToolActivityStatus::Unknown
    );
}
#[test]
fn pending_calls_and_large_record_budgets_fail_without_unbounded_allocation() {
    let mut rows = vec![header(), message("caller", "assistant", "tools")];
    rows.extend((0..257).map(|index|json!({"type":"function_call","callId":format!("call-{index}"),"messageId":"caller","name":"synthetic-tool"})));
    let result = WorkBuddyAdapter::new().parse(&bytes(&rows), &mut CapturingSink::default());
    assert!(matches!(result, Err(ProviderError::StructuralFatal(_))));
    let body = "x".repeat(STREAM_RECORD_MAX_BYTES as usize);
    let result = WorkBuddyAdapter::new().parse(
        &bytes(&[header(), message("large", "user", &body)]),
        &mut CapturingSink::default(),
    );
    assert!(matches!(result, Err(ProviderError::RecordTooLarge { .. })));
    let body = "中  ".repeat(32_768);
    let (report, sink) = parse(&bytes(&[header(), message("bounded-large", "user", &body)]));
    assert_eq!(report.committed, 1);
    assert_eq!(sink.messages[0].text, body);
}
struct ChunkedSource {
    bytes: Vec<u8>,
    opens: AtomicUsize,
}
impl ReadOnlySource for ChunkedSource {
    fn len(&self) -> u64 {
        self.bytes.len() as u64
    }
    fn open(&self) -> PortResult<Box<dyn BufRead + Send + '_>> {
        self.opens.fetch_add(1, Ordering::SeqCst);
        Ok(Box::new(BufReader::with_capacity(
            7,
            Cursor::new(&self.bytes),
        )))
    }
}
#[test]
fn streaming_and_byte_parse_keep_exact_events_and_append_prefix_spans() {
    let prefix = bytes(&[header(), message("first", "user", "prefix")]);
    let (before, sink) = parse(&prefix);
    let mut extended = prefix.clone();
    extended.extend(bytes(&[message("second", "assistant", "append")]));
    let source = ChunkedSource {
        bytes: extended.clone(),
        opens: AtomicUsize::new(0),
    };
    let mut streamed = CapturingSink::default();
    let after = WorkBuddyAdapter::new()
        .parse_source(&source, &mut streamed)
        .unwrap();
    assert_eq!(before.committed, 1);
    assert_eq!(after.committed, 2);
    assert!(source.opens.load(Ordering::SeqCst) >= 2);
    assert_eq!(streamed.messages[0].text, sink.messages[0].text);
    assert_eq!(streamed.messages[0].span, sink.messages[0].span);
    assert_eq!(source.bytes, extended);
    assert_eq!(
        parse(&extended).1.messages[1].span,
        streamed.messages[1].span
    );
}
struct FailingSink;
impl CanonicalEventSink for FailingSink {
    fn emit_message(&mut self, _event: MessageEvent<'_>) -> PortResult<()> {
        Err(PortError::Backend("synthetic private sink detail".into()))
    }
}
#[test]
fn sink_failure_returns_stable_private_error_without_false_commit_report() {
    let error = WorkBuddyAdapter::new()
        .parse(
            &bytes(&[header(), message("first", "user", "body")]),
            &mut FailingSink,
        )
        .unwrap_err();
    assert!(matches!(error, ProviderError::Io(_)));
    assert!(!error.to_string().contains("synthetic private sink detail"));
}

#[test]
fn unanchored_adjacent_tool_records_and_explicit_cli_host_kind_are_not_workbuddy_proof() {
    let rows = [
        header(),
        message("caller", "assistant", "tools"),
        json!({"type":"function_call","callId":"adjacent","name":"synthetic-tool"}),
        json!({"type":"function_call_result","callId":"adjacent","status":"success"}),
    ];
    let (report, sink) = parse(&bytes(&rows));
    assert_eq!(report.skipped, 0);
    assert!(sink.activities.is_empty());
    let mut foreign = header();
    foreign["meta"]["codebuddy.ai/hostKind"] = json!("cli");
    let input = bytes(&[foreign, message("caller", "assistant", "text")]);
    assert_eq!(
        WorkBuddyAdapter::new().probe(&input).unwrap().confidence,
        Confidence::Ambiguous
    );
}

#[test]
fn explicit_cli_marker_on_a_message_overrides_local_marker_evidence() {
    let adapter = WorkBuddyAdapter::new();
    for kind in ["cli", "codebuddy-cli", "tencent-codebuddy"] {
        let mut foreign = message("native", "user", "synthetic body");
        foreign["meta"] = json!({"codebuddy.ai/hostKind":kind});
        for input in [bytes(&[foreign.clone()]), bytes(&[header(), foreign])] {
            assert_eq!(
                adapter.probe(&input).unwrap().confidence,
                Confidence::Ambiguous
            );
            assert!(matches!(
                adapter.parse(&input, &mut CapturingSink::default()),
                Err(ProviderError::AmbiguousVariant(_))
            ));
        }
    }
}

#[test]
fn malformed_optional_tool_identities_never_establish_success_or_borrow_a_caller() {
    use agent_session_grep_domain::ToolActivityStatus;
    for field in ["sessionId", "messageId"] {
        for invalid in [json!(27), json!(true), json!([]), json!({}), json!("  ")] {
            let mut bad_result = json!({"type":"function_call_result","callId":"known",
                "status":"success"});
            bad_result[field] = invalid.clone();
            let (report, sink) = parse(&bytes(&[
                header(),
                message("caller", "assistant", "tools"),
                json!({"type":"function_call","callId":"known","messageId":"caller",
                    "name":"synthetic-tool","arguments":{}}),
                bad_result,
            ]));
            assert_eq!(report.skipped, 0);
            assert_eq!(sink.activities.len(), 1);
            assert_eq!(
                sink.activities[0].activity.status,
                ToolActivityStatus::Unknown
            );

            let mut bad_call = json!({"type":"function_call","callId":"invalid",
                "messageId":"caller","name":"synthetic-tool","arguments":{}});
            bad_call[field] = invalid;
            let (report, sink) = parse(&bytes(&[
                header(),
                message("caller", "assistant", "tools"),
                bad_call,
                json!({"type":"function_call_result","callId":"invalid","status":"success"}),
            ]));
            assert_eq!(report.skipped, 0);
            assert!(sink.activities.is_empty());
        }
    }
}
