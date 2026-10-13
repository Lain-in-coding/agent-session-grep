//! Golden 契约测试：固定 fixture 字节 → pinned canonical 输出。
//!
//! 任何 parser 行为漂移（角色映射、文本抽取、span 计算、计数口径）或
//! fixture 字节漂移（git 行尾转换、误编辑）都必须在此响亮失败，作为
//! Beta 认证的可复核证据。fixture 为纯合成数据，来源与覆盖点见
//! `tests/golden/PROVENANCE.md`。
//!
//! 全字段捕获 sink、fixture 读取与 BLAKE3 校验、canonical JSON 投影复用
//! `agent_session_grep_testkit::golden`，本文件只保留 grok 特有的 span↔chunk-kind
//! 断言与一个手动再生辅助。

use agent_session_grep_ports::{Confidence, ProviderAdapter};
use agent_session_grep_provider_grok::GrokBuildAdapter;
use agent_session_grep_testkit::assert_read_only;
use agent_session_grep_testkit::golden::{self, CapturingSink};
use serde_json::Value;

/// fixture 与期望文件随 crate 固定存放；以 manifest 目录定位，不依赖 cwd。
const FIXTURE_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/golden/basic.jsonl");
const EXPECTED_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/golden/basic.expected.json"
);
/// Reference ACP fixtures encode `content` as a single `{type:"text",text:…}`
/// object. `basic.jsonl` covers only string + array, so this shape previously
/// disappeared while every golden test still passed.
const OBJECT_CONTENT_FIXTURE_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/golden/object-content.jsonl"
);
const OBJECT_CONTENT_EXPECTED_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/golden/object-content.expected.json"
);

/// 解析 fixture：经共享 sink 全字段捕获，返回报告与 sink。
fn parse_fixture(bytes: &[u8]) -> (agent_session_grep_ports::ParseReport, CapturingSink) {
    golden::parse_golden(&GrokBuildAdapter::new(), bytes)
}

#[test]
fn probe_never_mutates_source_bytes() {
    let expected = golden::read_expected(EXPECTED_PATH);
    let bytes = golden::read_fixture_verified(FIXTURE_PATH, &expected);

    // RFC-0002 §7 的只读契约必须有可执行守护，不能只依赖代码审查。
    assert_read_only(&bytes, |source| GrokBuildAdapter::new().probe(source))
        .expect("golden fixture probe must succeed");
}

#[test]
fn parse_never_mutates_source_bytes() {
    let expected = golden::read_expected(EXPECTED_PATH);
    let bytes = golden::read_fixture_verified(FIXTURE_PATH, &expected);
    let mut sink = CapturingSink::default();

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
    // PRD R2.3：fixture 内置一条故意破损行——probe 必须容忍（≤3），不得
    // 整源拒绝；chunk 证据充分时保持 Confirmed。
    let expected = golden::read_expected(EXPECTED_PATH);
    let bytes = golden::read_fixture_verified(FIXTURE_PATH, &expected);
    let r = GrokBuildAdapter::new()
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

#[test]
fn tool_activity_stays_unsupported_because_activities_cannot_anchor() {
    // 双向钉住 tool_activity=Unsupported 的诚实性：
    // 1) 语料确含文档化的结构化工具记录（`content._meta.bashCommand` 元 chunk，
    //    adapter 作为非对话记录跳过）——格式有工具记录，不是"格式无记录"；
    // 2) 所有消息以空 native id 上报（ACP 无 per-message id，promptId 是 prompt
    //    级分组键），且 adapter 零 activity 输出——per RFC-0002 R5.3 + staging
    //    fail-closed，活动根本无法锚定，Unsupported 是唯一诚实声明。
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
        text.contains("\"bashCommand\""),
        "golden 语料必须保留文档化的 bashCommand 工具记录形状（如实承认格式有工具记录）"
    );
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
    let (report, sink) = parse_fixture(&bytes);
    println!(
        "{}",
        serde_json::to_string_pretty(&golden::canonical_json(&hash, &report, &sink.messages))
            .unwrap()
    );
}

#[test]
fn object_content_golden_canonical_output_is_pinned() {
    let expected = golden::read_expected(OBJECT_CONTENT_EXPECTED_PATH);
    let bytes = golden::read_fixture_verified(OBJECT_CONTENT_FIXTURE_PATH, &expected);
    let (report, sink) = golden::parse_golden(&GrokBuildAdapter::new(), &bytes);
    let hash = blake3::hash(&bytes).to_hex().to_string();
    let actual = golden::canonical_json(&hash, &report, &sink.messages);
    let actual_pretty = serde_json::to_string_pretty(&actual).expect("serialize actual");
    assert_eq!(
        actual, expected,
        "object-content canonical 输出与 pinned 期望不一致——parser 行为漂移或 fixture 未经评审变更。actual =\n{actual_pretty}"
    );
}

#[test]
fn object_content_golden_keeps_both_chunk_roles() {
    // 这条是本 fixture 存在的理由：对象形态的 user/assistant chunks 都必须进索引。
    let expected = golden::read_expected(OBJECT_CONTENT_EXPECTED_PATH);
    let bytes = golden::read_fixture_verified(OBJECT_CONTENT_FIXTURE_PATH, &expected);
    let (report, sink) = golden::parse_golden(&GrokBuildAdapter::new(), &bytes);
    assert_eq!(report.committed, 2);
    assert_eq!(
        sink.messages
            .iter()
            .map(|m| m.role.as_str())
            .collect::<Vec<_>>(),
        ["user", "assistant"]
    );
    assert_eq!(
        sink.messages
            .iter()
            .map(|m| m.text.as_str())
            .collect::<Vec<_>>(),
        ["object-shaped user", "object-shaped assistant"]
    );
}

#[test]
fn object_content_golden_probe_and_parse_never_mutate_source_bytes() {
    let expected = golden::read_expected(OBJECT_CONTENT_EXPECTED_PATH);
    let bytes = golden::read_fixture_verified(OBJECT_CONTENT_FIXTURE_PATH, &expected);
    assert_read_only(&bytes, |source| GrokBuildAdapter::new().probe(source))
        .expect("object-content golden probe must succeed");
    let mut sink = CapturingSink::default();
    let report = assert_read_only(&bytes, |source| {
        GrokBuildAdapter::new().parse(source, &mut sink)
    })
    .expect("object-content golden parse must succeed");
    assert_eq!(report.committed, sink.messages.len());
}

/// object-content fixture 的手动再生辅助。
#[test]
#[ignore = "manual regeneration helper — prints canonical JSON for object-content.expected.json"]
fn print_actual_object_content_canonical_output_for_regeneration() {
    let bytes =
        std::fs::read(OBJECT_CONTENT_FIXTURE_PATH).expect("read object-content.jsonl fixture");
    let hash = blake3::hash(&bytes).to_hex().to_string();
    let (report, sink) = golden::parse_golden(&GrokBuildAdapter::new(), &bytes);
    println!(
        "{}",
        serde_json::to_string_pretty(&golden::canonical_json(&hash, &report, &sink.messages))
            .unwrap()
    );
}
