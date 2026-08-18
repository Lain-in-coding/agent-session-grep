//! Golden 契约测试：固定 fixture 字节 → pinned canonical 输出。
//!
//! 任何 parser 行为漂移（角色映射、文本抽取、span 计算、计数口径）或
//! fixture 字节漂移（git 行尾转换、误编辑）都必须在此响亮失败，作为
//! Beta 认证的可复核证据。fixture 为纯合成数据，来源与覆盖点见
//! `tests/golden/PROVENANCE.md`。

use agent_session_grep_ports::{
    CanonicalEventSink, Confidence, MessageEvent, ParseReport, ProviderAdapter,
};
use agent_session_grep_provider_grok::GrokBuildAdapter;
use agent_session_grep_testkit::assert_read_only;
use serde_json::{Value, json};

/// fixture 与期望文件随 crate 固定存放；以 manifest 目录定位，不依赖 cwd。
const FIXTURE_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/golden/basic.jsonl");
const EXPECTED_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/golden/basic.expected.json"
);

/// 收集 emit 的消息事件。
#[derive(Default)]
struct CollectingSink {
    messages: Vec<Captured>,
}

/// 拍平的事件快照（`MessageEvent` 借用输入，测试侧需拥有所有权）。
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

/// 读取 pinned 期望输出。
fn read_expected() -> Value {
    let bytes = std::fs::read(EXPECTED_PATH).expect("read basic.expected.json");
    serde_json::from_slice(&bytes).expect("basic.expected.json must be valid JSON")
}

/// 读 fixture 字节并先校验 BLAKE3 指纹。
fn read_fixture_verified(expected: &Value) -> Vec<u8> {
    let bytes = std::fs::read(FIXTURE_PATH).expect("read basic.jsonl fixture");
    let actual = blake3::hash(&bytes).to_hex().to_string();
    let pinned = expected["fixture_blake3"]
        .as_str()
        .expect("expected.json must pin fixture_blake3");
    assert_eq!(
        actual, pinned,
        "fixture bytes drifted — check .gitattributes -text rules (actual blake3 = {actual})"
    );
    bytes
}

/// 用 adapter 解析 fixture，返回报告与收集到的事件。
fn parse_fixture(bytes: &[u8]) -> (ParseReport, Vec<Captured>) {
    let mut sink = CollectingSink::default();
    let report = GrokBuildAdapter::new()
        .parse(bytes, &mut sink)
        .expect("golden fixture parse must succeed");
    (report, sink.messages)
}

/// 把解析结果序列化为 canonical 输出形状。
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

    // RFC-0002 §7 的只读契约必须有可执行守护，不能只依赖代码审查。
    assert_read_only(&bytes, |source| GrokBuildAdapter::new().probe(source))
        .expect("golden fixture probe must succeed");
}

#[test]
fn parse_never_mutates_source_bytes() {
    let expected = read_expected();
    let bytes = read_fixture_verified(&expected);
    let mut sink = CollectingSink::default();

    let report = assert_read_only(&bytes, |source| {
        GrokBuildAdapter::new().parse(source, &mut sink)
    })
    .expect("golden fixture parse must succeed");
    assert!(report.committed > 0, "fixture must exercise message output");
    assert!(!sink.messages.is_empty(), "fixture must emit messages");
}

#[test]
fn golden_provenance_revision_matches_manifest() {
    assert_eq!(GrokBuildAdapter::new().manifest().fixture_revision, Some(1));
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
fn golden_probe_tolerates_intentional_broken_line() {
    // PRD R2.3：fixture 内置一条故意破损行——probe 必须容忍（≤3），不得
    // 整源拒绝；chunk 证据充分时保持 Confirmed。
    let expected = read_expected();
    let bytes = read_fixture_verified(&expected);
    let r = GrokBuildAdapter::new()
        .probe(&bytes)
        .expect("golden fixture probe must tolerate the broken line");
    assert_eq!(r.confidence, Confidence::Confirmed);
}

#[test]
fn golden_spans_slice_back_to_exact_source_lines() {
    let expected = read_expected();
    let bytes = read_fixture_verified(&expected);
    let (_, messages) = parse_fixture(&bytes);
    assert!(!messages.is_empty(), "golden fixture must emit messages");

    // 独立重建行表（split_inclusive + 去行尾），据此验证 span 契约：
    // span 恰好覆盖"某一整行去掉行尾符"。
    let text = std::str::from_utf8(&bytes).expect("fixture is UTF-8");
    let mut line_by_start = std::collections::HashMap::new();
    let mut offset = 0u64;
    for raw in text.split_inclusive('\n') {
        let start = offset;
        offset += raw.len() as u64;
        let line = raw.strip_suffix('\n').unwrap_or(raw);
        let line = line.strip_suffix('\r').unwrap_or(line);
        line_by_start.insert(start, line);
    }

    for m in &messages {
        let (start, end) = m.span.expect("golden message must carry a span");
        let line = line_by_start
            .get(&start)
            .unwrap_or_else(|| panic!("span.start={start} is not the start of any source line"));
        assert_eq!(
            end - start,
            line.len() as u64,
            "seq={}: span 长度必须等于源记录行（去行尾）字节长",
            m.seq
        );
        let slice = &bytes[start as usize..end as usize];
        assert_eq!(
            slice,
            line.as_bytes(),
            "seq={}: span 切片必须与源记录行逐字节一致",
            m.seq
        );
        // span 指向的必须是"它自己"的记录：chunk 种类与消息角色一致。
        let record: Value =
            serde_json::from_slice(slice).expect("span slice must be a complete JSON record");
        let kind = record["params"]["update"]["sessionUpdate"]
            .as_str()
            .unwrap_or("");
        let expected_kind = match m.role.as_str() {
            "user" => "user_message_chunk",
            "assistant" => "agent_message_chunk",
            other => panic!("unexpected role {other}"),
        };
        assert_eq!(
            kind, expected_kind,
            "seq={}: span 指向的 chunk 种类必须与消息角色一致",
            m.seq
        );
    }
}

/// 手动再生辅助：fixture 合法变更（PROVENANCE.md 的 fixture_revision 递增）后，
/// 运行下面命令打印新的 canonical JSON，人工审阅后粘贴回 basic.expected.json：
///
/// ```text
/// cargo test -p agent-session-grep-provider-grok --test golden -- --ignored --nocapture
/// ```
#[test]
#[ignore = "manual regeneration helper — prints canonical JSON for basic.expected.json"]
fn print_actual_canonical_output_for_regeneration() {
    let bytes = std::fs::read(FIXTURE_PATH).expect("read basic.jsonl fixture");
    let hash = blake3::hash(&bytes).to_hex().to_string();
    let (report, messages) = parse_fixture(&bytes);
    println!(
        "{}",
        serde_json::to_string_pretty(&canonical_json(&hash, &report, &messages)).unwrap()
    );
}
