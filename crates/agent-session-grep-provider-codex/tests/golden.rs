//! Golden 契约测试：把 `tests/golden/basic.jsonl` 的解析输出逐字段钉死在
//! `tests/golden/basic.expected.json`——任何 parser 行为变化都必须显式更新
//! expected 才能通过，防止 canonical 输出无声漂移。
//!
//! 字节精确性：fixture 的**磁盘字节**是权威输入，expected 里钉了它的 BLAKE3
//! 指纹。若 git 换行转换或编辑器改写了字节，先在指纹断言处响亮失败，
//! 而不是留到后面变成难懂的 span 错位。

use agent_session_grep_ports::{CanonicalEventSink, Confidence, MessageEvent, ProviderAdapter};
use agent_session_grep_provider_codex::CodexAdapter;
use agent_session_grep_testkit::assert_read_only;
use serde_json::{Value, json};
use std::path::PathBuf;

/// 收集 emit 的消息事件（各 provider crate 测试各自持有收集器的既有先例）。
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

fn golden_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("golden")
}

fn read_fixture_bytes() -> Vec<u8> {
    std::fs::read(golden_dir().join("basic.jsonl")).expect("read tests/golden/basic.jsonl")
}

/// 解析 fixture 并构造与 basic.expected.json 同形的 canonical JSON。
fn parse_to_canonical_json(bytes: &[u8]) -> Value {
    let mut sink = CollectingSink::default();
    let report = CodexAdapter::new()
        .parse(bytes, &mut sink)
        .expect("golden fixture must parse");
    let messages: Vec<Value> = sink
        .messages
        .iter()
        .map(|m| {
            let (start, end) = m
                .span
                .expect("codex adapter must attribute a span per message");
            json!({
                "seq": m.seq,
                "native_id": m.native_id,
                "parent_native_id": m.parent_native_id,
                "role": m.role,
                "text": m.text,
                "timestamp": m.timestamp,
                "is_sidechain": m.is_sidechain,
                "span": {"start": start, "end": end},
            })
        })
        .collect();
    json!({
        "fixture_blake3": blake3::hash(bytes).to_hex().as_str(),
        "session_native_id": report.session_native_id,
        "committed": report.committed,
        "skipped": report.skipped,
        "messages": messages,
    })
}

#[test]
fn probe_never_mutates_source_bytes() {
    let bytes = read_fixture_bytes();

    // RFC-0002 §7 的只读契约必须有可执行守护，不能只依赖代码审查。
    assert_read_only(&bytes, |source| CodexAdapter::new().probe(source))
        .expect("golden fixture probe must succeed");
}

#[test]
fn parse_never_mutates_source_bytes() {
    let bytes = read_fixture_bytes();
    let mut sink = CollectingSink::default();

    // parse 是实际产出路径；运行时指纹断言守护 RFC-0002 §7 的源只读契约。
    let report = assert_read_only(&bytes, |source| {
        CodexAdapter::new().parse(source, &mut sink)
    })
    .expect("golden fixture must parse");
    assert!(report.committed > 0, "fixture must exercise message output");
    assert!(!sink.messages.is_empty(), "fixture must emit messages");
}

#[test]
fn golden_provenance_revision_matches_manifest() {
    assert_eq!(CodexAdapter::new().manifest().fixture_revision, Some(1));
}

#[test]
fn golden_basic_matches_pinned_canonical_output() {
    let bytes = read_fixture_bytes();
    let expected: Value = serde_json::from_slice(
        &std::fs::read(golden_dir().join("basic.expected.json"))
            .expect("read tests/golden/basic.expected.json"),
    )
    .expect("basic.expected.json must be valid JSON");

    // 先验字节指纹：最常见的漂移来源是 git eol 转换（autocrlf），
    // 必须在这里失败并给出可行动的修复指向。
    let actual_hash = blake3::hash(&bytes).to_hex().to_string();
    let pinned_hash = expected["fixture_blake3"].as_str().unwrap_or_default();
    assert_eq!(
        actual_hash, pinned_hash,
        "fixture bytes drifted — check .gitattributes -text rules \
         (on-disk blake3 = {actual_hash}, pinned = {pinned_hash})"
    );

    let actual = parse_to_canonical_json(&bytes);
    assert_eq!(
        actual,
        expected,
        "canonical output drifted from basic.expected.json; actual =\n{}",
        serde_json::to_string_pretty(&actual).unwrap()
    );
}

#[test]
fn golden_probe_tolerates_intentional_broken_line() {
    // PRD R2.3：fixture 内置一条故意破损行——probe 必须容忍（≤3），不得
    // 整源拒绝；置信度降一档（无破损时为 Confirmed → High），保持 adapter 认领。
    let bytes = read_fixture_bytes();
    let r = CodexAdapter::new()
        .probe(&bytes)
        .expect("golden fixture probe must tolerate the broken line");
    assert_eq!(r.confidence, Confidence::High);
}

#[test]
fn golden_basic_spans_slice_back_to_source_envelope_lines() {
    let bytes = read_fixture_bytes();
    let mut sink = CollectingSink::default();
    CodexAdapter::new()
        .parse(&bytes, &mut sink)
        .expect("golden fixture must parse");
    assert!(!sink.messages.is_empty(), "fixture must emit messages");

    // 独立于 parser 重新计算每行的字节区间（与 parse 相同的行语义：
    // split_inclusive + 去掉行尾 \n / \r\n），span 必须精确落在某一行上。
    let text = std::str::from_utf8(&bytes).expect("fixture is UTF-8");
    let mut line_spans: Vec<(u64, u64, &str)> = Vec::new();
    let mut offset = 0u64;
    for raw_line in text.split_inclusive('\n') {
        let start = offset;
        offset += raw_line.len() as u64;
        let line = raw_line.strip_suffix('\n').unwrap_or(raw_line);
        let line = line.strip_suffix('\r').unwrap_or(line);
        line_spans.push((start, start + line.len() as u64, line));
    }

    for m in &sink.messages {
        let (start, end) = m.span.expect("span required");
        let (_, line_end, line) = line_spans
            .iter()
            .find(|(s, _, _)| *s == start)
            .unwrap_or_else(|| {
                panic!(
                    "span.start {start} does not land on any line start (native_id={})",
                    m.native_id
                )
            });
        assert_eq!(
            end, *line_end,
            "span.end must equal the line end (native_id={})",
            m.native_id
        );
        // span 切片必须等于来源封套行的原始字节。
        assert_eq!(
            &bytes[start as usize..end as usize],
            line.as_bytes(),
            "span slice must equal the source envelope line (native_id={})",
            m.native_id
        );
        // 且来源行必须是权威 response_item/message 封套——绝不是 event_msg 镜像。
        let v: Value = serde_json::from_str(line).expect("span target line must be valid JSON");
        assert_eq!(
            v["type"], "response_item",
            "span must point at an authoritative envelope (native_id={})",
            m.native_id
        );
        assert_eq!(
            v["payload"]["type"], "message",
            "span must point at a message payload (native_id={})",
            m.native_id
        );
        assert_eq!(
            v["payload"]["id"].as_str(),
            Some(m.native_id.as_str()),
            "span target line must carry the same native id"
        );
    }
}

/// 手动再生辅助：fixture 合法变更（PROVENANCE.md 的 fixture_revision 递增）后，
/// 运行下面命令打印新的 canonical JSON，人工审阅后粘贴回 basic.expected.json：
///
/// ```text
/// cargo test -p agent-session-grep-provider-codex --test golden -- --ignored --nocapture
/// ```
#[test]
#[ignore = "manual regeneration helper — prints canonical JSON for basic.expected.json"]
fn print_actual_canonical_output_for_regeneration() {
    let bytes = read_fixture_bytes();
    println!(
        "{}",
        serde_json::to_string_pretty(&parse_to_canonical_json(&bytes)).unwrap()
    );
}
