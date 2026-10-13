//! 生命周期回归（B5）：append / shrink / 同长改写 / 分叉 parent 边 / 移动 / WAL。
//!
//! 六类生命周期场景通过下列具名测试固定其解析与恢复合同；
//! 本文件是公开树内可核查的 provider 层证据。
//!
//! - append / shrink / 同长改写：parser 只按当前快照字节产出——未变化的记录
//!   逐字段（含 span）与旧快照一致，被截断的尾部如实计入 skipped，绝不缓存
//!   或复用旧解析结果（不推进成功水位/不覆盖 last-good 由 store 层负责）。
//! - 分叉 parent 边：`parentUuid` 原样透传——兄弟记录共享同一父边，悬空父边
//!   保留给跨源解析，绝不按"父是否在本文件出现"裁剪。
//! - 文件移动：provider 层 N/A——`ProviderAdapter::parse` 只接收已验证快照字节
//!   （`crates/agent-session-grep-ports/src/lib.rs:1613`），adapter 拿不到路径，
//!   身份只来自记录内 native id（`src/lib.rs:1041` 的 `native_id: &rec.uuid`）；
//!   locator/历史不变的移动语义由 store 层守护
//!   （`crates/agent-session-grep-adapters-sqlite/src/relocation/tests.rs:468`）。
//! - SQLite WAL：本 provider 源为 JSONL，N/A；WAL 读取证据在
//!   `crates/agent-session-grep-adapters-sqlite/src/source_fs.rs:309`。

use agent_session_grep_ports::{
    CanonicalEventSink, MessageEvent, ParseReport, PortResult, ProviderAdapter,
};
use agent_session_grep_provider_claude::ClaudeCodeAdapter;
use serde_json::{Value, json};

const SESSION: &str = "lifecycle-session-0001";

/// 收集 emit 的消息事件（各测试目标自持本地 helper，与既有套件同构）。
#[derive(Default)]
struct CollectingSink {
    messages: Vec<Captured>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
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
    fn emit_message(&mut self, event: MessageEvent<'_>) -> PortResult<()> {
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

/// 合成一条记录（形状对齐 golden fixture 的顶层字段）。
fn record(uuid: &str, parent: Option<&str>, role: &str, text: &str, sidechain: bool) -> Value {
    let kind = if role == "assistant" {
        "assistant"
    } else {
        "user"
    };
    json!({
        "parentUuid": parent,
        "isSidechain": sidechain,
        "type": kind,
        "message": {"role": role, "content": text},
        "uuid": uuid,
        "timestamp": "2026-01-01T00:00:00.000Z",
        "sessionId": SESSION,
    })
}

/// 把记录渲染为 JSONL 快照字节（每行 LF 结尾）。
fn render(records: &[Value]) -> Vec<u8> {
    let mut out = String::new();
    for r in records {
        out.push_str(&serde_json::to_string(r).expect("render record"));
        out.push('\n');
    }
    out.into_bytes()
}

/// 解析快照；生命周期场景下必须整体成功（坏行只降级）。
fn parse_ok(bytes: &[u8]) -> (ParseReport, Vec<Captured>) {
    let mut sink = CollectingSink::default();
    let report = ClaudeCodeAdapter::new()
        .parse(bytes, &mut sink)
        .expect("lifecycle fixture parse must succeed");
    (report, sink.messages)
}

fn m1() -> Value {
    record("lifecycle-m1", None, "user", "first message", false)
}

fn m2() -> Value {
    record(
        "lifecycle-m2",
        Some("lifecycle-m1"),
        "assistant",
        "second message",
        false,
    )
}

fn m3() -> Value {
    record(
        "lifecycle-m3",
        Some("lifecycle-m2"),
        "user",
        "third message",
        false,
    )
}

// ---- append ----

#[test]
fn append_keeps_existing_ids_spans_and_seq_byte_stable() {
    let base = render(&[m1(), m2()]);
    let appended_line = serde_json::to_string(&m3()).expect("render appended");
    let append_start = base.len() as u64;
    let mut extended = base.clone();
    extended.extend_from_slice(appended_line.as_bytes());
    extended.push(b'\n');

    let (base_report, base_msgs) = parse_ok(&base);
    let (ext_report, ext_msgs) = parse_ok(&extended);

    assert_eq!(base_report.committed, 2);
    assert_eq!(ext_report.committed, 3, "追加一条记录只新增一条消息");
    assert_eq!(
        ext_msgs[..2],
        base_msgs[..],
        "追加不得移动既有消息的 seq/native_id/parent/text/span"
    );
    assert_eq!(ext_msgs[2].native_id, "lifecycle-m3");
    assert_eq!(
        ext_msgs[2].span,
        Some((append_start, append_start + appended_line.len() as u64)),
        "新消息 span 必须覆盖追加行（不含行尾）"
    );
}

// ---- shrink ----

#[test]
fn shrink_at_line_boundary_reproduces_prefix_parse_exactly() {
    let full = render(&[m1(), m2(), m3()]);
    let (_, full_msgs) = parse_ok(&full);
    let boundary = full.len() - (serde_json::to_string(&m3()).unwrap().len() + 1);
    let (report, prefix_msgs) = parse_ok(&full[..boundary]);

    assert_eq!(report.committed, 2);
    assert_eq!(report.skipped, 0);
    assert_eq!(
        prefix_msgs,
        full_msgs[..2],
        "按行边界截断后，剩余消息必须与完整快照的前缀逐字段一致"
    );
}

#[test]
fn shrink_torn_tail_is_skipped_recoverably_without_shifting_prefix() {
    let full = render(&[m1(), m2(), m3()]);
    let third_len = serde_json::to_string(&m3()).unwrap().len();
    let third_start = full.len() - (third_len + 1);
    // 撕裂写入：只留下第三行的前 16 字节（截断的 JSON，无行尾）。
    let mut torn = full.clone();
    torn.truncate(third_start + 16);

    let (report, msgs) = parse_ok(&torn);
    let (_, full_msgs) = parse_ok(&full);

    assert_eq!(report.committed, 2, "撕裂尾巴不得吞掉或伪造消息");
    assert_eq!(report.skipped, 1, "撕裂的半行必须如实计入 skipped");
    assert_eq!(report.diagnostics.len(), 1);
    assert_eq!(
        msgs,
        full_msgs[..2],
        "撕裂行之后的字节不存在；此前消息必须与完整快照前缀一致"
    );
}

#[test]
fn shrink_to_empty_source_yields_empty_report_without_fabrication() {
    let (report, msgs) = parse_ok(b"");
    assert_eq!(report.committed, 0);
    assert_eq!(report.skipped, 0);
    assert!(msgs.is_empty());
    assert_eq!(report.session_native_id, None);
}

// ---- 同长改写 ----

#[test]
fn same_length_text_rewrite_updates_text_and_keeps_identity_and_span() {
    let original = record("lifecycle-rw", None, "user", "aaaa0000", false);
    let original_line = serde_json::to_string(&original).unwrap();
    let base = format!("{original_line}\n").into_bytes();
    let (_, base_msgs) = parse_ok(&base);

    let rewritten_line = original_line.replace("aaaa0000", "bbbb1111");
    assert_eq!(
        rewritten_line.len(),
        original_line.len(),
        "测试前提：同长改写"
    );
    let rewritten = format!("{rewritten_line}\n").into_bytes();
    let (report, rewritten_msgs) = parse_ok(&rewritten);

    assert_eq!(report.committed, 1);
    assert_eq!(rewritten_msgs[0].text, "bbbb1111");
    assert_eq!(rewritten_msgs[0].native_id, "lifecycle-rw");
    assert_eq!(
        rewritten_msgs[0].span, base_msgs[0].span,
        "同长改写后 span 区间不变，但正文必须来自当前字节"
    );
}

#[test]
fn same_length_uuid_rewrite_changes_identity_without_stale_cache() {
    let original = record("lifecycle-id-a", None, "user", "stable text", false);
    let original_line = serde_json::to_string(&original).unwrap();
    let base = format!("{original_line}\n").into_bytes();
    let (_, base_msgs) = parse_ok(&base);

    let rewritten_line = original_line.replace("lifecycle-id-a", "lifecycle-id-b");
    assert_eq!(rewritten_line.len(), original_line.len());
    let rewritten = format!("{rewritten_line}\n").into_bytes();
    let (_, rewritten_msgs) = parse_ok(&rewritten);

    assert_eq!(
        rewritten_msgs[0].native_id, "lifecycle-id-b",
        "改写后的 native id 必须立即生效——绝不复用旧快照的身份/水位"
    );
    assert_eq!(rewritten_msgs[0].text, "stable text");
    assert_eq!(rewritten_msgs[0].span, base_msgs[0].span);
}

// ---- 分叉 parent 边 ----

#[test]
fn fork_siblings_keep_shared_parent_edge_and_sidechain_flag_verbatim() {
    let root = record("lifecycle-fork-root", None, "user", "fork root", false);
    let reply = record(
        "lifecycle-fork-reply",
        Some("lifecycle-fork-root"),
        "assistant",
        "main reply",
        false,
    );
    let branch_a = record(
        "lifecycle-fork-a",
        Some("lifecycle-fork-root"),
        "user",
        "branch A prompt",
        false,
    );
    let branch_b = record(
        "lifecycle-fork-b",
        Some("lifecycle-fork-root"),
        "user",
        "branch B prompt",
        true,
    );
    let snapshot = render(&[root, reply, branch_a, branch_b]);
    let (report, msgs) = parse_ok(&snapshot);

    assert_eq!(report.committed, 4);
    assert_eq!(
        msgs.iter()
            .map(|m| m.parent_native_id.clone())
            .collect::<Vec<_>>(),
        vec![
            None,
            Some("lifecycle-fork-root".to_string()),
            Some("lifecycle-fork-root".to_string()),
            Some("lifecycle-fork-root".to_string()),
        ],
        "兄弟分叉必须共享同一父边，而不是被折叠或重排"
    );
    assert_eq!(
        msgs.iter().map(|m| m.is_sidechain).collect::<Vec<_>>(),
        vec![false, false, false, true],
        "isSidechain 必须原样透传"
    );
    assert_eq!(
        msgs.iter().map(|m| m.seq).collect::<Vec<_>>(),
        vec![0, 1, 2, 3],
        "文件顺序即 seq 顺序，分叉不重排"
    );
}

#[test]
fn fork_dangling_parent_edge_is_preserved_for_cross_source_resolution() {
    // 分叉/续写文件从中间开始：首条记录的父消息不在本文件里。
    let child = record(
        "lifecycle-copied-child",
        Some("lifecycle-parent-outside-file"),
        "assistant",
        "copied branch tail",
        true,
    );
    let snapshot = render(&[child]);
    let (_, msgs) = parse_ok(&snapshot);
    assert_eq!(
        msgs[0].parent_native_id.as_deref(),
        Some("lifecycle-parent-outside-file"),
        "悬空父边必须原样保留，跨源解析是 store 的职责，adapter 不得裁剪"
    );

    // 空串 parentUuid 语义等价 null（根消息）。
    let root = record("lifecycle-empty-parent", Some(""), "user", "root", false);
    let (_, msgs) = parse_ok(&render(&[root]));
    assert_eq!(msgs[0].parent_native_id, None);
}
