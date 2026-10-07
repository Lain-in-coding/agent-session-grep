//! Golden 契约测试：固定 fixture 字节 → pinned canonical 输出。
//!
//! 任何 parser 行为漂移（角色映射、文本抽取、span 计算、计数口径）或
//! fixture 字节漂移（git 行尾转换、误编辑）都必须在此响亮失败，作为
//! Beta 认证的可复核证据。fixture 为纯合成数据，来源与覆盖点见
//! `tests/golden/PROVENANCE.md`。
//!
//! 全字段捕获 sink、fixture 读取与 BLAKE3 校验、canonical JSON 投影复用
//! `agent_session_grep_testkit::golden`，本文件只保留 qoder 特有的 span↔record
//! 断言与一个手动再生辅助。

use agent_session_grep_ports::{Confidence, ProviderAdapter};
use agent_session_grep_provider_qoder::QoderAdapter;
use agent_session_grep_testkit::assert_read_only;
use agent_session_grep_testkit::golden::{self, CapturingSink};
use serde_json::Value;

const FIXTURE_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/golden/basic.jsonl");
const EXPECTED_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/golden/basic.expected.json"
);

/// 解析 fixture：经共享 sink 全字段捕获，返回报告与 sink。
fn parse_fixture(bytes: &[u8]) -> (agent_session_grep_ports::ParseReport, CapturingSink) {
    golden::parse_golden(&QoderAdapter::new(), bytes)
}

#[test]
fn probe_never_mutates_source_bytes() {
    let expected = golden::read_expected(EXPECTED_PATH);
    let bytes = golden::read_fixture_verified(FIXTURE_PATH, &expected);
    assert_read_only(&bytes, |source| QoderAdapter::new().probe(source))
        .expect("golden fixture probe must succeed");
}

#[test]
fn parse_never_mutates_source_bytes() {
    let expected = golden::read_expected(EXPECTED_PATH);
    let bytes = golden::read_fixture_verified(FIXTURE_PATH, &expected);
    let mut sink = CapturingSink::default();
    let report = assert_read_only(&bytes, |source| {
        QoderAdapter::new().parse(source, &mut sink)
    })
    .expect("golden fixture parse must succeed");
    assert!(report.committed > 0, "fixture must exercise message output");
    assert!(!sink.messages.is_empty(), "fixture must emit messages");
}

#[test]
fn golden_provenance_revision_matches_manifest() {
    assert_eq!(QoderAdapter::new().manifest().fixture_revision, Some(1));
}

#[test]
fn golden_canonical_output_is_pinned() {
    let expected = golden::read_expected(EXPECTED_PATH);
    let bytes = golden::read_fixture_verified(FIXTURE_PATH, &expected);
    let (report, sink) = parse_fixture(&bytes);
    let hash = blake3::hash(&bytes).to_hex().to_string();
    let actual = golden::canonical_json(&hash, &report, &sink.messages);
    let actual_pretty = serde_json::to_string_pretty(&actual).expect("serialize actual");
    assert_eq!(
        actual, expected,
        "canonical 输出与 pinned 期望不一致——parser 行为漂移或 fixture 未经评审变更。actual =\n{actual_pretty}"
    );
}

#[test]
fn golden_probe_tolerates_intentional_broken_line() {
    let expected = golden::read_expected(EXPECTED_PATH);
    let bytes = golden::read_fixture_verified(FIXTURE_PATH, &expected);
    let r = QoderAdapter::new()
        .probe(&bytes)
        .expect("golden fixture probe must tolerate the broken line");
    assert_eq!(r.confidence, Confidence::Confirmed);
}

#[test]
fn golden_spans_slice_back_to_exact_source_lines() {
    let expected = golden::read_expected(EXPECTED_PATH);
    let bytes = golden::read_fixture_verified(FIXTURE_PATH, &expected);
    let (_, sink) = parse_fixture(&bytes);
    let messages = &sink.messages;
    assert!(!messages.is_empty(), "golden fixture must emit messages");

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

    for m in messages {
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
        // Qoder 的聊天记录 type 即角色：span 指向的 type 必须等于消息角色。
        let record: Value =
            serde_json::from_slice(slice).expect("span slice must be a complete JSON record");
        assert_eq!(
            record["type"].as_str().unwrap_or(""),
            m.role,
            "seq={}: span 指向记录的 type 必须等于消息角色",
            m.seq
        );
    }
}

#[test]
fn tool_activity_stays_unsupported_because_activities_cannot_anchor() {
    // 双向钉住 tool_activity=Unsupported 的诚实性：
    // 1) 语料确含文档化的结构化工具记录（`tool_use`/`tool_result` 记录类型，
    //    adapter 作为非对话记录跳过）——格式有工具记录，不是"格式无记录"；
    // 2) 所有消息以空 native id 上报（user/assistant 记录无 per-message id），
    //    且 adapter 零 activity 输出——per RFC-0002 R5.3 + staging fail-closed，
    //    活动根本无法锚定，Unsupported 是唯一诚实声明。
    // 未来若格式获得 per-message id，本测试的断言会失败，强制重评 capability。
    let expected = golden::read_expected(EXPECTED_PATH);
    let bytes = golden::read_fixture_verified(FIXTURE_PATH, &expected);
    let (report, sink) = parse_fixture(&bytes);
    assert!(report.committed > 0, "fixture must exercise message output");
    assert!(
        sink.activities.is_empty(),
        "adapter 不得发出无法锚定的 activity（空 native id 会被 staging fail-closed 丢弃）"
    );
    assert!(
        !sink.messages.is_empty() && sink.messages.iter().all(|m| m.native_id.trim().is_empty()),
        "golden 消息全部以空 native id 上报——若未来带上 per-message id，\
         capability.rs 的 tool_activity 声明必须重新评估"
    );
    let text = std::str::from_utf8(&bytes).expect("fixture is UTF-8");
    assert!(
        text.contains("\"tool_use\"") && text.contains("\"tool_result\""),
        "golden 语料必须保留文档化的 tool_use/tool_result 工具记录形状（如实承认格式有工具记录）"
    );
}

/// 手动再生辅助：
/// ```text
/// cargo test -p agent-session-grep-provider-qoder --test golden -- --ignored --nocapture
/// ```
#[test]
#[ignore = "manual regeneration helper — prints canonical JSON for basic.expected.json"]
fn print_actual_canonical_output_for_regeneration() {
    let bytes = std::fs::read(FIXTURE_PATH).expect("read basic.jsonl fixture");
    let hash = blake3::hash(&bytes).to_hex().to_string();
    let (report, sink) = parse_fixture(&bytes);
    println!(
        "{}",
        serde_json::to_string_pretty(&golden::canonical_json(&hash, &report, &sink.messages))
            .unwrap()
    );
}
