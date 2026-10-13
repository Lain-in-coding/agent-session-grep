//! Golden 契约测试：固定 fixture 字节 → pinned canonical 输出。
//!
//! 任何 parser 行为漂移（角色映射、文本抽取、span 计算、计数口径）或 fixture
//! 字节漂移（git 行尾转换、误编辑）都必须在此响亮失败，作为 Beta 认证的可复核
//! 证据。fixture 为纯合成数据，来源与覆盖点见 `tests/golden/PROVENANCE.md`。
//!
//! Aider 是 Markdown 聊天历史：span 是**派生近似**（块起始行 + 文本长度），
//! 不是逐字节的整行切片——见 capability.rs `source_span: derived`。
//!
//! 全字段捕获 sink、fixture 读取与 BLAKE3 校验、canonical JSON 投影复用
//! `agent_session_grep_testkit::golden`，本文件只保留 aider 特有的派生近似
//! span 断言与一个手动再生辅助。

use agent_session_grep_ports::{Confidence, ProviderAdapter};
use agent_session_grep_provider_aider::AiderAdapter;
use agent_session_grep_testkit::assert_read_only;
use agent_session_grep_testkit::golden::{self, CapturingSink};

const FIXTURE_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/golden/basic.md");
const EXPECTED_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/golden/basic.expected.json"
);
/// 多行提示语料：连续的 `#### ` 行是一条提示，另含 aider 空输入的裸 `####`
/// 与工具输出的裸 `>`。`basic.md` 一条都不覆盖。
const MULTILINE_FIXTURE_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/golden/multiline-prompt.md"
);
const MULTILINE_EXPECTED_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/golden/multiline-prompt.expected.json"
);

/// 解析 fixture：经共享 sink 全字段捕获，返回报告与 sink。
fn parse_fixture(bytes: &[u8]) -> (agent_session_grep_ports::ParseReport, CapturingSink) {
    golden::parse_golden(&AiderAdapter::new(), bytes)
}

#[test]
fn probe_never_mutates_source_bytes() {
    let expected = golden::read_expected(EXPECTED_PATH);
    let bytes = golden::read_fixture_verified(FIXTURE_PATH, &expected);
    assert_read_only(&bytes, |source| AiderAdapter::new().probe(source))
        .expect("golden fixture probe must succeed");
}

#[test]
fn parse_never_mutates_source_bytes() {
    let expected = golden::read_expected(EXPECTED_PATH);
    let bytes = golden::read_fixture_verified(FIXTURE_PATH, &expected);
    let mut sink = CapturingSink::default();
    let report = assert_read_only(&bytes, |source| {
        AiderAdapter::new().parse(source, &mut sink)
    })
    .expect("golden fixture parse must succeed");
    assert!(report.committed > 0, "fixture must exercise message output");
    assert!(!sink.messages.is_empty(), "fixture must emit messages");
}

#[test]
fn golden_provenance_revision_matches_manifest() {
    assert_eq!(AiderAdapter::new().manifest().fixture_revision, Some(1));
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
fn golden_probe_confirms_fixture() {
    // Aider 是 Markdown 历史：probe 采样非空行，header + `#### ` 提示齐备即 Confirmed。
    let expected = golden::read_expected(EXPECTED_PATH);
    let bytes = golden::read_fixture_verified(FIXTURE_PATH, &expected);
    let r = AiderAdapter::new()
        .probe(&bytes)
        .expect("golden fixture probe must succeed");
    assert_eq!(r.confidence, Confidence::Confirmed);
}

#[test]
fn golden_spans_are_derived_approximations() {
    // Aider span 是派生近似（capability `derived`）：start 必须落在某条源行的
    // 行首，end 与 start 的差必须等于消息文本长度——span + 文本可重建消息块，
    // 但 span 不保证逐字节切片等于文本（blockquote `> ` 前缀与 trim 会偏移）。
    let expected = golden::read_expected(EXPECTED_PATH);
    let bytes = golden::read_fixture_verified(FIXTURE_PATH, &expected);
    let (_, sink) = parse_fixture(&bytes);
    let messages = &sink.messages;
    assert!(!messages.is_empty(), "golden fixture must emit messages");

    let text = std::str::from_utf8(&bytes).expect("fixture is UTF-8");
    let mut line_starts: Vec<u64> = Vec::new();
    let mut offset = 0u64;
    for raw in text.split_inclusive('\n') {
        line_starts.push(offset);
        offset += raw.len() as u64;
    }

    for m in messages {
        let (start, end) = m.span.expect("golden message must carry a span");
        assert!(
            line_starts.contains(&start),
            "seq={}: span.start={start} 必须是某条源行的行首",
            m.seq
        );
        assert_eq!(
            end - start,
            m.text.len() as u64,
            "seq={}: span 长度必须等于消息文本长度（派生近似契约）",
            m.seq
        );
    }
}

/// 手动再生辅助：
/// ```text
/// cargo test -p agent-session-grep-provider-aider --test golden -- --ignored --nocapture
/// ```
#[test]
#[ignore = "manual regeneration helper — prints canonical JSON for basic.expected.json"]
fn print_actual_canonical_output_for_regeneration() {
    let bytes = std::fs::read(FIXTURE_PATH).expect("read basic.md fixture");
    let hash = blake3::hash(&bytes).to_hex().to_string();
    let (report, sink) = parse_fixture(&bytes);
    println!(
        "{}",
        serde_json::to_string_pretty(&golden::canonical_json(&hash, &report, &sink.messages))
            .unwrap()
    );
}

// ---- 多行提示与裸标记语料（multiline-prompt.md）----
//
// `basic.md` 里每条 `#### ` 提示都只有一行，也没有裸 `####` / `>` 标记，
// 于是"多行提示被切成 N 条单行消息"与"裸标记被当成助手正文"两个缺陷在
// golden 全绿的情况下存活了下来。

#[test]
fn multiline_golden_canonical_output_is_pinned() {
    let expected = golden::read_expected(MULTILINE_EXPECTED_PATH);
    let bytes = golden::read_fixture_verified(MULTILINE_FIXTURE_PATH, &expected);
    let (report, sink) = parse_fixture(&bytes);
    let hash = blake3::hash(&bytes).to_hex().to_string();
    let actual = golden::canonical_json(&hash, &report, &sink.messages);
    let actual_pretty = serde_json::to_string_pretty(&actual).expect("serialize actual");
    assert_eq!(
        actual, expected,
        "multiline canonical 输出与 pinned 期望不一致——parser 行为漂移或 fixture 未经评审变更。actual =\n{actual_pretty}"
    );
}

#[test]
fn multiline_golden_keeps_one_prompt_as_one_message() {
    // 这条是本 fixture 存在的理由：连续 `#### ` 行是**一条**提示，必须以一条
    // 消息进索引，否则跨行短语检索不到；裸 `####` 不得变成助手正文。
    let expected = golden::read_expected(MULTILINE_EXPECTED_PATH);
    let bytes = golden::read_fixture_verified(MULTILINE_FIXTURE_PATH, &expected);
    let (report, sink) = parse_fixture(&bytes);
    let users: Vec<&str> = sink
        .messages
        .iter()
        .filter(|m| m.role == "user")
        .map(|m| m.text.as_str())
        .collect();
    assert_eq!(
        users.len(),
        1,
        "三行连续提示必须合成一条 user 消息：{users:?}"
    );
    assert_eq!(users[0].lines().count(), 3, "三行正文必须都在同一条消息里");
    for m in &sink.messages {
        assert!(
            !m.text.trim().is_empty(),
            "seq={}: 不得出现空正文消息",
            m.seq
        );
        assert_ne!(m.text.trim(), "####", "裸 `####` 不得成为消息正文");
        assert!(
            !m.text.contains("####"),
            "seq={}: 提示标记不得进入正文：{:?}",
            m.seq,
            m.text
        );
    }
    assert_eq!(report.committed, sink.messages.len());
}

#[test]
fn multiline_golden_probe_and_parse_never_mutate_source_bytes() {
    let expected = golden::read_expected(MULTILINE_EXPECTED_PATH);
    let bytes = golden::read_fixture_verified(MULTILINE_FIXTURE_PATH, &expected);
    assert_read_only(&bytes, |source| AiderAdapter::new().probe(source))
        .expect("multiline golden probe must succeed");
    let mut sink = CapturingSink::default();
    let report = assert_read_only(&bytes, |source| {
        AiderAdapter::new().parse(source, &mut sink)
    })
    .expect("multiline golden parse must succeed");
    assert_eq!(report.committed, sink.messages.len());
}

/// multiline fixture 的手动再生辅助（输出写入 `multiline-prompt.expected.json`）。
#[test]
#[ignore = "manual regeneration helper — prints canonical JSON for multiline-prompt.expected.json"]
fn print_actual_multiline_canonical_output_for_regeneration() {
    let bytes = std::fs::read(MULTILINE_FIXTURE_PATH).expect("read multiline-prompt.md fixture");
    let hash = blake3::hash(&bytes).to_hex().to_string();
    let (report, sink) = parse_fixture(&bytes);
    println!(
        "{}",
        serde_json::to_string_pretty(&golden::canonical_json(&hash, &report, &sink.messages))
            .unwrap()
    );
}
