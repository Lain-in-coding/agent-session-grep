//! Golden contract test for the additive `hermes/sqlite-state-v1` variant.
//!
//! The fixture (`tests/golden/state.db`) is a synthetic SQLite database built by
//! `tests/golden/generate_sqlite_fixture.py`; its BLAKE3 fingerprint is pinned
//! in `tests/golden/sqlite.expected.json`. The projection below pins the parts
//! the shared `testkit::golden` scaffold cannot express for a multi-session
//! SQLite source: per-message session membership, the parse accounting and the
//! diagnostics that carry the row-level states.

use agent_session_grep_ports::{
    CanonicalEventSink, Confidence, MessageEvent, ParseReport, ProviderAdapter, ProviderError,
    ToolActivityEvent,
};
use agent_session_grep_provider_hermes::OpenHermesAdapter;
use agent_session_grep_testkit::assert_read_only;
use serde_json::json;

const VARIANT_ID: &str = "hermes/sqlite-state-v1";
const FIXTURE_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/golden/state.db");
const EXPECTED_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/golden/sqlite.expected.json"
);

#[derive(Default)]
struct SessionSink {
    messages: Vec<Captured>,
    activities: usize,
}

struct Captured {
    seq: u32,
    session: Option<String>,
    native_id: String,
    role: String,
    text: String,
    timestamp: Option<String>,
    is_sidechain: bool,
    span: Option<(u64, u64)>,
}

impl CanonicalEventSink for SessionSink {
    fn emit_message(
        &mut self,
        event: MessageEvent<'_>,
    ) -> agent_session_grep_ports::PortResult<()> {
        self.messages.push(Captured {
            seq: event.seq,
            session: event.session.map(|identity| identity.source_key.clone()),
            native_id: event.native_id.to_string(),
            role: event.role.to_string(),
            text: event.text.to_string(),
            timestamp: event.timestamp.map(str::to_string),
            is_sidechain: event.is_sidechain,
            span: event.span,
        });
        Ok(())
    }

    fn emit_activity(
        &mut self,
        _event: ToolActivityEvent<'_>,
    ) -> agent_session_grep_ports::PortResult<()> {
        self.activities += 1;
        Ok(())
    }
}

fn parse_fixture(bytes: &[u8]) -> (ParseReport, SessionSink) {
    let mut sink = SessionSink::default();
    let report = OpenHermesAdapter::new()
        .parse(bytes, &mut sink)
        .expect("golden fixture parse must succeed");
    (report, sink)
}

fn canonical_json(hash: &str, report: &ParseReport, sink: &SessionSink) -> serde_json::Value {
    json!({
        "fixture_blake3": hash,
        "variant_id": VARIANT_ID,
        "session_native_id": report.session_native_id,
        "multi_session": report.session_observation.multi_session,
        "committed": report.committed,
        "skipped": report.skipped,
        "activities": sink.activities,
        "messages": sink
            .messages
            .iter()
            .map(|message| {
                json!({
                    "seq": message.seq,
                    "session": message.session,
                    "native_id": message.native_id,
                    "role": message.role,
                    "text": message.text,
                    "timestamp": message.timestamp,
                    "is_sidechain": message.is_sidechain,
                    "span": message.span.map(|(start, end)| json!({"start": start, "end": end})),
                })
            })
            .collect::<Vec<_>>(),
        "diagnostics": report.diagnostics,
    })
}

#[test]
fn probe_confirms_the_state_db_fixture_as_the_sqlite_variant() {
    let bytes = std::fs::read(FIXTURE_PATH).expect("read state.db fixture");
    let probe = OpenHermesAdapter::new()
        .probe(&bytes)
        .expect("state.db fixture probe must succeed");
    assert_eq!(probe.variant_id, VARIANT_ID);
    assert_eq!(probe.confidence, Confidence::Confirmed);
    assert!(
        probe
            .matched_evidence
            .iter()
            .any(|line| line.contains("messages(id, session_id, role, content")),
        "{:?}",
        probe.matched_evidence
    );
}

#[test]
fn golden_state_db_output_is_pinned() {
    let expected = serde_json::from_slice::<serde_json::Value>(
        &std::fs::read(EXPECTED_PATH).expect("read sqlite.expected.json"),
    )
    .expect("sqlite.expected.json must be valid JSON");
    let bytes = std::fs::read(FIXTURE_PATH).expect("read state.db fixture");
    let actual_hash = blake3::hash(&bytes).to_hex().to_string();
    assert_eq!(
        actual_hash,
        expected["fixture_blake3"].as_str().expect("pinned hash"),
        "state.db fixture bytes drifted - regenerate only with review"
    );

    let (report, sink) = parse_fixture(&bytes);
    let actual = canonical_json(&actual_hash, &report, &sink);
    let actual_pretty = serde_json::to_string_pretty(&actual).expect("serialize actual");
    assert_eq!(
        actual, expected,
        "canonical sqlite-state-v1 output drifted from the pinned expectation. actual =\n{actual_pretty}"
    );
}

#[test]
fn golden_state_db_never_emits_tool_activity_or_spans() {
    let bytes = std::fs::read(FIXTURE_PATH).expect("read state.db fixture");
    let (_, sink) = parse_fixture(&bytes);
    assert!(!sink.messages.is_empty(), "fixture must emit messages");
    assert_eq!(
        sink.activities, 0,
        "every tool association is non-authoritative - no activity may be emitted"
    );
    assert!(
        sink.messages.iter().all(|message| message.span.is_none()),
        "a SQLite row has no contiguous byte span in the verified snapshot"
    );
    assert!(
        sink.messages
            .iter()
            .all(|message| message.native_id.is_empty()),
        "rowids are per-database and must not be adopted as native message ids"
    );
}

#[test]
fn probe_and_parse_never_mutate_the_received_snapshot_bytes() {
    let bytes = std::fs::read(FIXTURE_PATH).expect("read state.db fixture");
    let adapter = OpenHermesAdapter::new();
    assert_read_only(&bytes, |source| adapter.probe(source))
        .expect("golden fixture probe must succeed");
    let mut sink = SessionSink::default();
    let report = assert_read_only(&bytes, |source| adapter.parse(source, &mut sink))
        .expect("golden fixture parse must succeed");
    assert!(report.committed > 0);
}

#[test]
fn probe_rejects_non_state_db_bytes() {
    let adapter = OpenHermesAdapter::new();
    let bytes = std::fs::read(FIXTURE_PATH).expect("read state.db fixture");
    // Truncating the SQLite header keeps it "a database-shaped file" that is
    // not this variant; the JSON session fixture is a different stream again.
    let err = adapter
        .probe(&bytes[..8])
        .expect_err("truncated header must not be claimed");
    assert!(matches!(err, ProviderError::AmbiguousVariant(_)));
}

#[test]
#[ignore = "manual regeneration helper - prints canonical JSON for sqlite.expected.json"]
fn print_actual_canonical_output_for_regeneration() {
    let bytes = std::fs::read(FIXTURE_PATH).expect("read state.db fixture");
    let hash = blake3::hash(&bytes).to_hex().to_string();
    let (report, sink) = parse_fixture(&bytes);
    println!(
        "{}",
        serde_json::to_string_pretty(&canonical_json(&hash, &report, &sink)).unwrap()
    );
}
