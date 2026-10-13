//! Golden contract test for the additive `cursor/disk-kv-v1` variant.
//!
//! The fixtures (`tests/golden/disk-kv.db` and `disk-kv-shuffled.db`) are
//! synthetic SQLite databases built by `tests/golden/generate_diskkv_fixture.py`
//! with the same logical content but different KV insertion orders. Their
//! BLAKE3 fingerprints are pinned in `tests/golden/disk-kv.expected.json`.
//!
//! The projection below pins the parts the shared `testkit::golden` scaffold
//! cannot express for a multi-session SQLite source: per-message session
//! membership, the parse accounting and the diagnostics that carry the
//! per-slot states and the verbatim composer/bubble ids.

use agent_session_grep_ports::{
    CanonicalEventSink, Confidence, MessageEvent, ParseReport, ProviderAdapter,
};
use agent_session_grep_provider_cursor::CursorAdapter;
use agent_session_grep_testkit::assert_read_only;
use serde_json::json;

const VARIANT_ID: &str = "cursor/disk-kv-v1";
const ITEM_TABLE_VARIANT_ID: &str = "cursor/vscdb-chat-v1";
const FIXTURE_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/golden/disk-kv.db");
const SHUFFLED_FIXTURE_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/golden/disk-kv-shuffled.db"
);
const ITEM_TABLE_FIXTURE_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/golden/basic.db");
const EXPECTED_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/golden/disk-kv.expected.json"
);

#[derive(Default)]
struct DiskKvSink {
    messages: Vec<Captured>,
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

impl CanonicalEventSink for DiskKvSink {
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
}

fn parse_fixture(bytes: &[u8]) -> (ParseReport, DiskKvSink) {
    let mut sink = DiskKvSink::default();
    let report = CursorAdapter::new()
        .parse(bytes, &mut sink)
        .expect("golden fixture parse must succeed");
    (report, sink)
}

fn canonical_json(
    hash: &str,
    shuffled_hash: &str,
    report: &ParseReport,
    sink: &DiskKvSink,
) -> serde_json::Value {
    json!({
        "fixture_blake3": hash,
        "shuffled_fixture_blake3": shuffled_hash,
        "variant_id": VARIANT_ID,
        "session_native_id": report.session_native_id,
        "multi_session": report.session_observation.multi_session,
        "committed": report.committed,
        "skipped": report.skipped,
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
fn probe_confirms_the_disk_kv_fixture_as_the_disk_kv_variant() {
    let bytes = std::fs::read(FIXTURE_PATH).expect("read disk-kv.db fixture");
    let probe = CursorAdapter::new()
        .probe(&bytes)
        .expect("disk-kv fixture probe must succeed");
    assert_eq!(probe.variant_id, VARIANT_ID);
    assert_eq!(probe.confidence, Confidence::Confirmed);
    assert!(
        probe
            .matched_evidence
            .iter()
            .any(|line| line.contains("cursorDiskKV(key, value)")),
        "{:?}",
        probe.matched_evidence
    );
}

#[test]
fn golden_disk_kv_output_is_pinned() {
    let expected = agent_session_grep_testkit::golden::read_expected(EXPECTED_PATH);
    let bytes = agent_session_grep_testkit::golden::read_fixture_verified(FIXTURE_PATH, &expected);
    let actual_hash = blake3::hash(&bytes).to_hex().to_string();

    let shuffled = std::fs::read(SHUFFLED_FIXTURE_PATH).expect("read shuffled fixture");
    let shuffled_hash = blake3::hash(&shuffled).to_hex().to_string();
    let (report, sink) = parse_fixture(&bytes);
    let actual = canonical_json(&actual_hash, &shuffled_hash, &report, &sink);
    let actual_pretty = serde_json::to_string_pretty(&actual).expect("serialize actual");
    assert_eq!(
        actual, expected,
        "canonical disk-kv output drifted from the pinned expectation. actual =\n{actual_pretty}"
    );
}

#[test]
fn golden_disk_kv_keeps_native_ids_as_verbatim_observations() {
    let bytes = std::fs::read(FIXTURE_PATH).expect("read disk-kv.db fixture");
    let (report, sink) = parse_fixture(&bytes);

    assert!(
        sink.messages
            .iter()
            .all(|message| message.native_id.is_empty()),
        "a composer-scoped bubble id is not a proven native message id"
    );
    assert!(
        sink.messages.iter().all(|message| message.span.is_none()),
        "a SQLite row has no contiguous byte span in the verified snapshot"
    );
    assert!(
        sink.messages
            .iter()
            .all(|message| message.timestamp.is_none()),
        "the disk-kv variant does not invent timestamps"
    );
    assert!(
        sink.messages
            .iter()
            .all(|message| matches!(message.role.as_str(), "user" | "assistant")),
        "only header roles 1/2 are emitted"
    );

    let notes = report.diagnostics.join("\n");
    // The verbatim composer id and a defect slot's exact storage key are the
    // observations; nothing is normalized, split or hashed.
    assert!(notes.contains("cmp:\u{96ea}/#%_e\u{301}"), "{notes}");
    assert!(
        notes.contains("`bubbleId:cmp:\u{96ea}/#%_e\u{301}:bad:json/\u{96ea}#%`"),
        "{notes}"
    );
    // The ok slot whose id carries `:` and a non-BMP emoji resolved through its
    // verbatim storage key, and its text is the stored bytes, untrimmed.
    assert!(
        sink.messages
            .iter()
            .any(|message| message.text == "  first \u{96ea} e\u{301}  "),
        "{:?}",
        sink.messages
            .iter()
            .map(|message| message.text.as_str())
            .collect::<Vec<_>>()
    );
    // The session identity carries the composer id verbatim, too.
    assert!(
        sink.messages
            .iter()
            .any(|message| message.session.as_deref() == Some("cmp:\u{96ea}/#%_e\u{301}")),
        "{:?}",
        sink.messages
            .iter()
            .map(|message| message.session.as_deref())
            .collect::<Vec<_>>()
    );
}

#[test]
fn golden_disk_kv_insertion_order_does_not_change_the_output() {
    let expected = agent_session_grep_testkit::golden::read_expected(EXPECTED_PATH);
    let bytes = agent_session_grep_testkit::golden::read_fixture_verified(FIXTURE_PATH, &expected);
    let shuffled = std::fs::read(SHUFFLED_FIXTURE_PATH).expect("read disk-kv-shuffled.db fixture");

    let pinned_shuffled = expected["shuffled_fixture_blake3"]
        .as_str()
        .expect("expected.json must pin shuffled_fixture_blake3");
    assert_eq!(
        blake3::hash(&shuffled).to_hex().to_string(),
        pinned_shuffled,
        "shuffled fixture bytes drifted - regenerate only with review"
    );

    let primary_hash = blake3::hash(&bytes).to_hex().to_string();
    let shuffled_hash = blake3::hash(&shuffled).to_hex().to_string();
    let (report, sink) = parse_fixture(&bytes);
    let (shuffled_report, shuffled_sink) = parse_fixture(&shuffled);

    // Compare the *whole* canonical projection - every message field
    // (native_id/timestamp/is_sidechain/span included) plus the report level
    // session, accounting and diagnostics. The two fixture hashes are fixture
    // identity rather than projection facts, so both sides receive the same
    // pair (the bytes themselves are pinned above and by
    // `read_fixture_verified`).
    let projection = canonical_json(&primary_hash, &shuffled_hash, &report, &sink);
    let shuffled_projection = canonical_json(
        &primary_hash,
        &shuffled_hash,
        &shuffled_report,
        &shuffled_sink,
    );
    let shuffled_pretty =
        serde_json::to_string_pretty(&shuffled_projection).expect("serialize shuffled projection");
    assert_eq!(
        projection, shuffled_projection,
        "the whole canonical projection must be independent of the KV insertion order \
         (messages follow fullConversationHeadersOnly). shuffled =\n{shuffled_pretty}"
    );
}

#[test]
fn probe_and_parse_never_mutate_the_received_snapshot_bytes() {
    let bytes = std::fs::read(FIXTURE_PATH).expect("read disk-kv.db fixture");
    let adapter = CursorAdapter::new();
    assert_read_only(&bytes, |source| adapter.probe(source))
        .expect("golden fixture probe must succeed");
    let mut sink = DiskKvSink::default();
    let report = assert_read_only(&bytes, |source| adapter.parse(source, &mut sink))
        .expect("golden fixture parse must succeed");
    assert!(report.committed > 0);
}

#[test]
fn golden_item_table_fixture_still_probes_as_the_item_table_variant() {
    // The additive variant must not steal the pre-existing surface.
    let bytes = std::fs::read(ITEM_TABLE_FIXTURE_PATH).expect("read basic.db fixture");
    let probe = CursorAdapter::new()
        .probe(&bytes)
        .expect("item-table fixture probe must succeed");
    assert_eq!(probe.variant_id, ITEM_TABLE_VARIANT_ID);
}

/// Manual regeneration helper:
/// ```text
/// cargo test -p agent-session-grep-provider-cursor --test disk_kv_golden -- --ignored --nocapture
/// ```
#[test]
#[ignore = "manual regeneration helper - prints canonical JSON for disk-kv.expected.json"]
fn print_actual_canonical_output_for_regeneration() {
    let bytes = std::fs::read(FIXTURE_PATH).expect("read disk-kv.db fixture");
    let shuffled = std::fs::read(SHUFFLED_FIXTURE_PATH).expect("read shuffled fixture");
    let hash = blake3::hash(&bytes).to_hex().to_string();
    let (report, sink) = parse_fixture(&bytes);
    let shuffled_hash = blake3::hash(&shuffled).to_hex().to_string();
    let value = canonical_json(&hash, &shuffled_hash, &report, &sink);
    println!("{}", serde_json::to_string_pretty(&value).unwrap());
}
