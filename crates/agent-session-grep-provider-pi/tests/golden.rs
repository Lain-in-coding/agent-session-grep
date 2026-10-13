//! Golden 契约测试：固定 fixture 字节 → pinned canonical 输出。
//!
//! 任何 parser 行为漂移（角色映射、文本抽取、span 计算、计数口径）或
//! fixture 字节漂移（git 行尾转换、误编辑）都必须在此响亮失败，作为
//! Beta 认证的可复核证据。fixture 为纯合成数据，来源与覆盖点见
//! `tests/golden/PROVENANCE.md`。
//!
//! 全字段捕获 sink、fixture 读取与 BLAKE3 校验、canonical JSON 投影复用
//! `agent_session_grep_testkit::golden`，本文件只保留 pi 特有的 span↔record
//! 断言与一个手动再生辅助。

use agent_session_grep_ports::{Confidence, ProviderAdapter};
use agent_session_grep_provider_pi::{PI_BRANCH_LINEAGE_DIAGNOSTIC_PREFIX, PiAdapter};
use agent_session_grep_testkit::assert_read_only;
use agent_session_grep_testkit::golden::{self, CapturingSink};
use serde_json::Value;

const FIXTURE_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/golden/basic.jsonl");
const EXPECTED_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/golden/basic.expected.json"
);
const V3_FIXTURE_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/golden/v3-branched.jsonl"
);
const V3_EXPECTED_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/golden/v3-branched.expected.json"
);
/// thinking 语料：正文只在 `thinking` 键上的 block。`basic.jsonl` 与
/// `v3-branched.jsonl` 的 content 块一律是 `{type:"text"}`（由
/// `golden_corpus_carries_no_tool_structure` 钉住），所以"thinking 正文被丢弃、
/// 记录随后被无声跳过"这个缺陷在 golden 全绿的情况下存活了下来。
const THINKING_FIXTURE_PATH: &str =
    concat!(env!("CARGO_MANIFEST_DIR"), "/tests/golden/thinking.jsonl");
const THINKING_EXPECTED_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/golden/thinking.expected.json"
);

/// 报告里的会话树血缘诊断条数（marker 由被测 crate 导出，避免测试侧硬编码漂移）。
fn lineage_diagnostics(report: &agent_session_grep_ports::ParseReport) -> Vec<&String> {
    report
        .diagnostics
        .iter()
        .filter(|d| d.starts_with(PI_BRANCH_LINEAGE_DIAGNOSTIC_PREFIX))
        .collect()
}

/// 解析 fixture：经共享 sink 全字段捕获，返回报告与 sink。
fn parse_fixture(bytes: &[u8]) -> (agent_session_grep_ports::ParseReport, CapturingSink) {
    golden::parse_golden(&PiAdapter::new(), bytes)
}

#[test]
fn probe_never_mutates_source_bytes() {
    let expected = golden::read_expected(EXPECTED_PATH);
    let bytes = golden::read_fixture_verified(FIXTURE_PATH, &expected);
    assert_read_only(&bytes, |source| PiAdapter::new().probe(source))
        .expect("golden fixture probe must succeed");
}

#[test]
fn parse_never_mutates_source_bytes() {
    let expected = golden::read_expected(EXPECTED_PATH);
    let bytes = golden::read_fixture_verified(FIXTURE_PATH, &expected);
    let mut sink = CapturingSink::default();
    let report = assert_read_only(&bytes, |source| PiAdapter::new().parse(source, &mut sink))
        .expect("golden fixture parse must succeed");
    assert!(report.committed > 0, "fixture must exercise message output");
    assert!(!sink.messages.is_empty(), "fixture must emit messages");
}

#[test]
fn golden_provenance_revision_matches_manifest() {
    assert_eq!(PiAdapter::new().manifest().fixture_revision, Some(1));
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
    let r = PiAdapter::new()
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
        // span 指向的必须是"它自己"的记录：type + message.role 与消息角色一致。
        let record: Value =
            serde_json::from_slice(slice).expect("span slice must be a complete JSON record");
        assert_eq!(
            record["type"], "message",
            "seq={}: span 必须指向 message 记录",
            m.seq
        );
        assert_eq!(
            record["message"]["role"].as_str().unwrap_or(""),
            m.role,
            "seq={}: span 指向记录的 message.role 必须等于消息角色",
            m.seq
        );
    }
}

#[test]
fn golden_corpus_carries_no_tool_structure() {
    // 钉住"本语料不含结构化工具调用记录"以及"adapter 零 activity 输出"这两个
    // 事实（capability.rs 的 tool_activity=Unsupported 依据）：语料中每条 message
    // 记录的 content 块只允许 {type:"text"} 形状。
    //
    // 口径澄清：Pi 的 v3 格式**确实**带 `{type:"toolCall"}` 块与
    // `message.role:"toolResult"` 记录（见 capability.rs pi 行的证据），
    // Unsupported 的含义是"adapter 未提取"，不是"格式没有"。因此本测试守的是
    // 语料边界——一旦哪天 fixture 引入工具块，说明提取范围要变，capability 声明与
    // adapter 提取必须同步评审，而不是让 fixture 悄悄跑在声明前面。
    let expected = golden::read_expected(EXPECTED_PATH);
    let bytes = golden::read_fixture_verified(FIXTURE_PATH, &expected);
    let (report, sink) = parse_fixture(&bytes);
    assert!(report.committed > 0, "fixture must exercise message output");
    assert!(
        sink.activities.is_empty(),
        "golden 语料不含可提取工具活动，adapter 不得发 activity"
    );
    let text = std::str::from_utf8(&bytes).expect("fixture is UTF-8");
    for line in text.lines() {
        let Ok(record) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        let Some(content) = record
            .get("message")
            .and_then(|m| m.get("content"))
            .filter(|c| c.is_array())
        else {
            continue;
        };
        for block in content.as_array().expect("array checked above") {
            assert_eq!(
                block
                    .get("type")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or(""),
                "text",
                "golden 语料出现非 text 的 content 块（{block}）：若这是新格式知识，\
                 capability.rs 的 tool_activity 声明与 adapter 提取必须同步升级"
            );
        }
    }
}

#[test]
fn v1_golden_reports_no_branch_lineage() {
    // 负向钉住：v1 语料（无 `version` 键、无 entry id/parentId）不得产生血缘诊断。
    // 若将来任何改动让诊断对线性语料也触发，它就从"可据以判断源是不是会话树"的
    // 事实退化成噪音。
    let expected = golden::read_expected(EXPECTED_PATH);
    let bytes = golden::read_fixture_verified(FIXTURE_PATH, &expected);
    let (report, _) = parse_fixture(&bytes);
    assert!(
        lineage_diagnostics(&report).is_empty(),
        "v1 golden 不得出现会话树血缘诊断，实际：{:?}",
        report.diagnostics
    );
}

#[test]
fn v3_golden_canonical_output_is_pinned() {
    let expected = golden::read_expected(V3_EXPECTED_PATH);
    let bytes = golden::read_fixture_verified(V3_FIXTURE_PATH, &expected);
    let (report, sink) = parse_fixture(&bytes);
    let hash = blake3::hash(&bytes).to_hex().to_string();
    let actual = golden::canonical_json(&hash, &report, &sink.messages);
    let actual_pretty = serde_json::to_string_pretty(&actual).expect("serialize actual");
    assert_eq!(
        actual, expected,
        "v3 canonical 输出与 pinned 期望不一致——parser 行为漂移或 fixture 未经评审变更。actual =\n{actual_pretty}"
    );
}

#[test]
fn v3_golden_probe_and_parse_never_mutate_source_bytes() {
    let expected = golden::read_expected(V3_EXPECTED_PATH);
    let bytes = golden::read_fixture_verified(V3_FIXTURE_PATH, &expected);
    assert_read_only(&bytes, |source| PiAdapter::new().probe(source))
        .expect("v3 golden fixture probe must succeed");
    let mut sink = CapturingSink::default();
    let report = assert_read_only(&bytes, |source| PiAdapter::new().parse(source, &mut sink))
        .expect("v3 golden fixture parse must succeed");
    assert_eq!(report.committed, sink.messages.len());
}

#[test]
fn v3_golden_indexes_every_branch_and_reports_lineage_exactly_once() {
    // 这条是本 fixture 存在的理由：v3 是 parent-linked 会话树（`aa000002` 有两个
    // 子记录），旧行为会把它按线性解析而**不留任何痕迹**。现在两条分支的正文都
    // 必须进索引（检索完整性），且恰好一条诊断如实说明"树未建模"。
    let expected = golden::read_expected(V3_EXPECTED_PATH);
    let bytes = golden::read_fixture_verified(V3_FIXTURE_PATH, &expected);
    let (report, sink) = parse_fixture(&bytes);

    let texts: Vec<&str> = sink.messages.iter().map(|m| m.text.as_str()).collect();
    assert!(
        texts.contains(&"kept\nanswer") && texts.contains(&"abandoned branch answer"),
        "同一 parentId 的两条分支都必须索引，实际：{texts:?}"
    );

    let lineage = lineage_diagnostics(&report);
    assert_eq!(
        lineage.len(),
        1,
        "v3 golden 必须恰好一条血缘诊断，实际：{:?}",
        report.diagnostics
    );
    assert!(
        lineage[0].contains("version=3") && lineage[0].contains("5 条记录带 parentId"),
        "诊断必须报出声明版本与血缘记录数（含非对话记录），实际：{}",
        lineage[0]
    );
}

#[test]
fn v3_golden_never_promotes_record_ids_to_native_identity() {
    // 与 capability.rs 的 `context=Unsupported` 互为凭证：v3 记录带 id/parentId，
    // 但事件一律以空 native_id + None parent 上报。要改这条必须同时改 capability
    // 列与 composition root 的消息身份策略（`derive_message_id` 逐字采用 native id，
    // 而 Pi 的 entry id 只在文件内唯一）。
    let expected = golden::read_expected(V3_EXPECTED_PATH);
    let bytes = golden::read_fixture_verified(V3_FIXTURE_PATH, &expected);
    let (_, sink) = parse_fixture(&bytes);
    assert!(!sink.messages.is_empty(), "v3 fixture must emit messages");
    for m in &sink.messages {
        assert!(
            m.native_id.is_empty(),
            "seq={}: Pi 不得把仅文件内唯一的 entry id 提升为 native 消息身份",
            m.seq
        );
        assert_eq!(
            m.parent_native_id, None,
            "seq={}: 不得发出 parent 边",
            m.seq
        );
        assert!(!m.is_sidechain, "seq={}: Pi 格式无 sidechain 概念", m.seq);
    }
}

#[test]
fn v3_golden_spans_slice_back_to_exact_source_lines() {
    let expected = golden::read_expected(V3_EXPECTED_PATH);
    let bytes = golden::read_fixture_verified(V3_FIXTURE_PATH, &expected);
    let (_, sink) = parse_fixture(&bytes);
    for m in &sink.messages {
        let (start, end) = m.span.expect("v3 golden message must carry a span");
        let slice = &bytes[start as usize..end as usize];
        let record: Value =
            serde_json::from_slice(slice).expect("span slice must be a complete JSON record");
        assert_eq!(record["type"], "message", "seq={}", m.seq);
        assert_eq!(
            record["message"]["role"].as_str().unwrap_or(""),
            m.role,
            "seq={}",
            m.seq
        );
    }
}

/// 手动再生辅助：
/// ```text
/// cargo test -p agent-session-grep-provider-pi --test golden -- --ignored --nocapture
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

/// v3 fixture 的手动再生辅助（同上，输出写入 `v3-branched.expected.json`）。
#[test]
#[ignore = "manual regeneration helper — prints canonical JSON for v3-branched.expected.json"]
fn print_actual_v3_canonical_output_for_regeneration() {
    let bytes = std::fs::read(V3_FIXTURE_PATH).expect("read v3-branched.jsonl fixture");
    let hash = blake3::hash(&bytes).to_hex().to_string();
    let (report, sink) = parse_fixture(&bytes);
    println!(
        "{}",
        serde_json::to_string_pretty(&golden::canonical_json(&hash, &report, &sink.messages))
            .unwrap()
    );
}

// ---- thinking 语料（thinking.jsonl）----

#[test]
fn thinking_golden_canonical_output_is_pinned() {
    let expected = golden::read_expected(THINKING_EXPECTED_PATH);
    let bytes = golden::read_fixture_verified(THINKING_FIXTURE_PATH, &expected);
    let (report, sink) = parse_fixture(&bytes);
    let hash = blake3::hash(&bytes).to_hex().to_string();
    let actual = golden::canonical_json(&hash, &report, &sink.messages);
    let actual_pretty = serde_json::to_string_pretty(&actual).expect("serialize actual");
    assert_eq!(
        actual, expected,
        "thinking canonical 输出与 pinned 期望不一致——parser 行为漂移或 fixture 未经评审变更。actual =\n{actual_pretty}"
    );
}

#[test]
fn thinking_golden_commits_every_prose_bearing_record() {
    // 这条是本 fixture 存在的理由：thinking-only 记录必须进索引。此前正文投影
    // 为空 → 落进 `text.trim().is_empty()` 的 `continue` 分支 → 既不 committed
    // 也不 skipped，记录彻底消失且报告里没有任何痕迹。
    let expected = golden::read_expected(THINKING_EXPECTED_PATH);
    let bytes = golden::read_fixture_verified(THINKING_FIXTURE_PATH, &expected);
    let (report, sink) = parse_fixture(&bytes);
    assert_eq!(report.committed, sink.messages.len());
    assert_eq!(
        report.committed, 4,
        "1 条 user + 3 条带正文的 assistant 都必须进索引：{report:?}"
    );
    for m in &sink.messages {
        assert!(
            !m.text.trim().is_empty(),
            "seq={}: thinking 语料不得出现空正文消息",
            m.seq
        );
    }
    // `toolCall` 块仍不进正文（capability.rs 的 tool_activity=Unsupported），
    // 且 adapter 依旧不发 activity。
    assert!(
        sink.activities.is_empty(),
        "pi 不得发出 activity（capability 声明 Unsupported）"
    );
    assert!(
        sink.messages.iter().all(|m| !m.text.contains("list_dir")),
        "toolCall 块不得进入正文：{:?}",
        sink.messages.iter().map(|m| &m.text).collect::<Vec<_>>()
    );
}

#[test]
fn thinking_golden_probe_and_parse_never_mutate_source_bytes() {
    let expected = golden::read_expected(THINKING_EXPECTED_PATH);
    let bytes = golden::read_fixture_verified(THINKING_FIXTURE_PATH, &expected);
    assert_read_only(&bytes, |source| PiAdapter::new().probe(source))
        .expect("thinking golden probe must succeed");
    let mut sink = CapturingSink::default();
    let report = assert_read_only(&bytes, |source| PiAdapter::new().parse(source, &mut sink))
        .expect("thinking golden parse must succeed");
    assert_eq!(report.committed, sink.messages.len());
}

/// thinking fixture 的手动再生辅助（输出写入 `thinking.expected.json`）。
#[test]
#[ignore = "manual regeneration helper — prints canonical JSON for thinking.expected.json"]
fn print_actual_thinking_canonical_output_for_regeneration() {
    let bytes = std::fs::read(THINKING_FIXTURE_PATH).expect("read thinking.jsonl fixture");
    let hash = blake3::hash(&bytes).to_hex().to_string();
    let (report, sink) = parse_fixture(&bytes);
    println!(
        "{}",
        serde_json::to_string_pretty(&golden::canonical_json(&hash, &report, &sink.messages))
            .unwrap()
    );
}
