//! Golden 契约测试：固定 fixture 字节 → pinned canonical 输出。
//!
//! 任何 parser 行为漂移（角色映射、文本抽取、计数口径）或 fixture 字节漂移
//! （误编辑）都必须在此响亮失败，作为 Beta 认证的可复核证据。fixture 为纯合成
//! 数据，来源与覆盖点见 `tests/golden/PROVENANCE.md`。
//!
//! OpenCode 是 SQLite（`opencode.db`）：无文件内字节 span（`span: None`），
//! span round-trip 标记 N/A。只读契约由 `assert_read_only` 守护——adapter 把
//! 字节写到临时文件并以 `SQLITE_OPEN_READONLY` 打开，绝不改写源。

use agent_session_grep_ports::{
    CanonicalEventSink, Confidence, MessageEvent, ParseReport, ProviderAdapter,
};
use agent_session_grep_provider_opencode::OpenCodeAdapter;
use agent_session_grep_testkit::assert_read_only;
use serde_json::{Value, json};

const FIXTURE_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/golden/basic.db");
const EXPECTED_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/golden/basic.expected.json"
);

#[derive(Default)]
struct CollectingSink {
    messages: Vec<Captured>,
}

struct Captured {
    seq: u32,
    native_id: String,
    parent_native_id: Option<String>,
    role: String,
    text: String,
    timestamp: Option<String>,
    is_sidechain: bool,
    span: Option<(u64, u64)>,
}

impl CanonicalEventSink for CollectingSink {
    fn emit_message(
        &mut self,
        event: MessageEvent<'_>,
    ) -> agent_session_grep_ports::PortResult<()> {
        self.messages.push(Captured {
            seq: event.seq,
            native_id: event.native_id.to_string(),
            parent_native_id: event.parent_native_id.map(str::to_string),
            role: event.role.to_string(),
            text: event.text.to_string(),
            timestamp: event.timestamp.map(str::to_string),
            is_sidechain: event.is_sidechain,
            span: event.span,
        });
        Ok(())
    }
}

fn read_expected() -> Value {
    let bytes = std::fs::read(EXPECTED_PATH).expect("read basic.expected.json");
    serde_json::from_slice(&bytes).expect("basic.expected.json must be valid JSON")
}

fn read_fixture_verified(expected: &Value) -> Vec<u8> {
    let bytes = std::fs::read(FIXTURE_PATH).expect("read basic.db fixture");
    let actual = blake3::hash(&bytes).to_hex().to_string();
    let pinned = expected["fixture_blake3"]
        .as_str()
        .expect("expected.json must pin fixture_blake3");
    assert_eq!(
        actual, pinned,
        "fixture bytes drifted — regenerate via generate_fixture.py (actual blake3 = {actual})"
    );
    bytes
}

fn parse_fixture(bytes: &[u8]) -> (ParseReport, Vec<Captured>) {
    let mut sink = CollectingSink::default();
    let report = OpenCodeAdapter::new()
        .parse(bytes, &mut sink)
        .expect("golden fixture parse must succeed");
    (report, sink.messages)
}

fn canonical_json(fixture_blake3: &str, report: &ParseReport, messages: &[Captured]) -> Value {
    json!({
        "fixture_blake3": fixture_blake3,
        "session_native_id": report.session_native_id,
        "committed": report.committed,
        "skipped": report.skipped,
        "messages": messages
            .iter()
            .map(|m| {
                json!({
                    "seq": m.seq,
                    "native_id": m.native_id,
                    "parent_native_id": m.parent_native_id,
                    "role": m.role,
                    "text": m.text,
                    "timestamp": m.timestamp,
                    "is_sidechain": m.is_sidechain,
                    "span": m.span.map(|(start, end)| json!({"start": start, "end": end})),
                })
            })
            .collect::<Vec<_>>(),
    })
}

#[test]
fn probe_never_mutates_source_bytes() {
    let expected = read_expected();
    let bytes = read_fixture_verified(&expected);
    assert_read_only(&bytes, |source| OpenCodeAdapter::new().probe(source))
        .expect("golden fixture probe must succeed");
}

#[test]
fn parse_never_mutates_source_bytes() {
    let expected = read_expected();
    let bytes = read_fixture_verified(&expected);
    let mut sink = CollectingSink::default();
    let report = assert_read_only(&bytes, |source| {
        OpenCodeAdapter::new().parse(source, &mut sink)
    })
    .expect("golden fixture parse must succeed");
    assert!(report.committed > 0, "fixture must exercise message output");
    assert!(!sink.messages.is_empty(), "fixture must emit messages");
}

#[test]
fn golden_provenance_revision_matches_manifest() {
    assert_eq!(OpenCodeAdapter::new().manifest().fixture_revision, Some(1));
}

#[test]
fn golden_canonical_output_is_pinned() {
    let expected = read_expected();
    let bytes = read_fixture_verified(&expected);
    let (report, messages) = parse_fixture(&bytes);
    let hash = blake3::hash(&bytes).to_hex().to_string();
    let actual = canonical_json(&hash, &report, &messages);
    let actual_pretty = serde_json::to_string_pretty(&actual).expect("serialize actual");
    assert_eq!(
        actual, expected,
        "canonical 输出与 pinned 期望不一致——parser 行为漂移或 fixture 未经评审变更。actual =\n{actual_pretty}"
    );
}

#[test]
fn golden_probe_confirms_fixture() {
    // SQLite：probe 校验 magic header + session/message/part 三表齐备即 Confirmed。
    let expected = read_expected();
    let bytes = read_fixture_verified(&expected);
    let r = OpenCodeAdapter::new()
        .probe(&bytes)
        .expect("golden fixture probe must succeed");
    assert_eq!(r.confidence, Confidence::Confirmed);
}

#[test]
fn golden_messages_carry_no_byte_span() {
    // SQLite 无文件内字节坐标：span round-trip 标记 N/A，全部消息 span 为 None。
    let expected = read_expected();
    let bytes = read_fixture_verified(&expected);
    let (_, messages) = parse_fixture(&bytes);
    assert!(!messages.is_empty(), "golden fixture must emit messages");
    assert!(
        messages.iter().all(|m| m.span.is_none()),
        "opencode 不应归因字节 span（N/A）"
    );
}

/// 手动再生辅助：
/// ```text
/// cargo test -p agent-session-grep-provider-opencode --test golden -- --ignored --nocapture
/// ```
#[test]
#[ignore = "manual regeneration helper — prints canonical JSON for basic.expected.json"]
fn print_actual_canonical_output_for_regeneration() {
    let bytes = std::fs::read(FIXTURE_PATH).expect("read basic.db fixture");
    let hash = blake3::hash(&bytes).to_hex().to_string();
    let (report, messages) = parse_fixture(&bytes);
    println!(
        "{}",
        serde_json::to_string_pretty(&canonical_json(&hash, &report, &messages)).unwrap()
    );
}
