//! 生命周期回归（B5）：append / shrink / 同长改写 / 分叉（无父边） / 移动 / WAL。
//!
//! 六类生命周期场景通过下列具名测试固定其解析与恢复合同；
//! 本文件是公开树内可核查的 provider 层证据。
//!
//! - append / shrink / 同长改写：parser 只按当前快照字节产出——未变化的记录
//!   逐字段（含 span、occurrence-local 时间戳规则）与旧快照一致，被截断的
//!   尾部如实跳过，绝不缓存或复用旧解析结果。
//! - 分叉 parent 边：Codex rollout 没有 `parentUuid` 字段（线性序列，见
//!   `src/lib.rs:1057` 的 `parent_native_id: None`）——本层 N/A；
//!   `linear_rollout_never_fabricates_parent_edges` 反向钉住"绝不臆造 threading"。
//! - 文件移动：provider 层 N/A——`ProviderAdapter::parse` 只接收已验证快照字节
//!   （`crates/agent-session-grep-ports/src/lib.rs:1613`），adapter 拿不到路径，
//!   身份只来自 payload id（`src/lib.rs:1055`）；locator/历史不变的移动语义由
//!   store 层守护
//!   （`crates/agent-session-grep-adapters-sqlite/src/relocation/tests.rs:468`）。
//! - SQLite WAL：本 provider 源为 JSONL，N/A；WAL 读取证据在
//!   `crates/agent-session-grep-adapters-sqlite/src/source_fs.rs:309`。

use agent_session_grep_ports::{
    CanonicalEventSink, MessageEvent, ParseReport, PortResult, ProviderAdapter,
};
use agent_session_grep_provider_codex::CodexAdapter;
use serde_json::{Value, json};

const SESSION: &str = "0198lifecycle000000000000000000";

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

/// 合成的 rollout 会话头（session_meta）。
fn session_meta() -> Value {
    json!({
        "timestamp": "2026-07-26T08:59:59.000Z",
        "type": "session_meta",
        "payload": {
            "session_id": SESSION,
            "cwd": "/synthetic/lifecycle",
            "originator": "codex_cli_rs",
            "cli_version": "0.0.0-lifecycle",
        },
    })
}

/// 合成一条权威 `response_item/message` 封套。
fn envelope(id: &str, role: &str, text: &str) -> Value {
    let block_type = if role == "assistant" {
        "output_text"
    } else {
        "input_text"
    };
    json!({
        "timestamp": "2026-07-26T09:00:00.000Z",
        "type": "response_item",
        "payload": {
            "type": "message",
            "id": id,
            "role": role,
            "content": [{"type": block_type, "text": text}],
        },
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
    let report = CodexAdapter::new()
        .parse(bytes, &mut sink)
        .expect("lifecycle fixture parse must succeed");
    (report, sink.messages)
}

fn m1() -> Value {
    envelope("lifecycle-cx-1", "user", "first rollout message")
}

fn m2() -> Value {
    envelope("lifecycle-cx-2", "assistant", "second rollout message")
}

fn m3() -> Value {
    envelope("lifecycle-cx-3", "user", "third rollout message")
}

// ---- append ----

#[test]
fn append_keeps_existing_ids_spans_and_seq_byte_stable() {
    let base = render(&[session_meta(), m1(), m2()]);
    let appended_line = serde_json::to_string(&m3()).expect("render appended");
    let append_start = base.len() as u64;
    let mut extended = base.clone();
    extended.extend_from_slice(appended_line.as_bytes());
    extended.push(b'\n');

    let (base_report, base_msgs) = parse_ok(&base);
    let (ext_report, ext_msgs) = parse_ok(&extended);

    assert_eq!(base_report.committed, 2);
    assert_eq!(ext_report.committed, 3, "追加一条记录只新增一条消息");
    assert_eq!(ext_report.session_native_id.as_deref(), Some(SESSION));
    assert_eq!(
        ext_msgs[..2],
        base_msgs[..],
        "追加不得移动既有消息的 seq/native_id/text/span"
    );
    assert_eq!(ext_msgs[2].native_id, "lifecycle-cx-3");
    assert_eq!(
        ext_msgs[2].span,
        Some((append_start, append_start + appended_line.len() as u64)),
        "新消息 span 必须覆盖追加行（不含行尾）"
    );
}

// ---- shrink ----

#[test]
fn shrink_at_line_boundary_reproduces_prefix_parse_exactly() {
    let full = render(&[session_meta(), m1(), m2(), m3()]);
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
    let full = render(&[session_meta(), m1(), m2(), m3()]);
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
    let original = envelope("lifecycle-cx-rw", "user", "aaaa0000");
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
    assert_eq!(rewritten_msgs[0].native_id, "lifecycle-cx-rw");
    assert_eq!(
        rewritten_msgs[0].timestamp, None,
        "外层 timestamp 是 occurrence-local，不得进入稳定字段"
    );
    assert_eq!(
        rewritten_msgs[0].span, base_msgs[0].span,
        "同长改写后 span 区间不变，但正文必须来自当前字节"
    );
}

#[test]
fn same_length_id_rewrite_changes_identity_without_stale_cache() {
    let original = envelope("lifecycle-cx-id-a", "user", "stable text");
    let original_line = serde_json::to_string(&original).unwrap();
    let base = format!("{original_line}\n").into_bytes();
    let (_, base_msgs) = parse_ok(&base);

    let rewritten_line = original_line.replace("lifecycle-cx-id-a", "lifecycle-cx-id-b");
    assert_eq!(rewritten_line.len(), original_line.len());
    let rewritten = format!("{rewritten_line}\n").into_bytes();
    let (_, rewritten_msgs) = parse_ok(&rewritten);

    assert_eq!(
        rewritten_msgs[0].native_id, "lifecycle-cx-id-b",
        "改写后的 native id 必须立即生效——绝不复用旧快照的身份/水位"
    );
    assert_eq!(rewritten_msgs[0].text, "stable text");
    assert_eq!(rewritten_msgs[0].span, base_msgs[0].span);
}

// ---- 分叉（N/A：无父边字段，反向钉住不臆造） ----

#[test]
fn linear_rollout_never_fabricates_parent_edges() {
    // 分叉文件保留了上一会话被复制的响应前缀（native id 重复出现）。
    // Codex 格式没有 parentUuid：adapter 必须原样 emit、绝不臆造 threading。
    let copied_prefix = [m1(), m2()];
    let new_tail = m3();
    let snapshot = render(&[
        session_meta(),
        copied_prefix[0].clone(),
        copied_prefix[1].clone(),
        new_tail,
    ]);
    let (report, msgs) = parse_ok(&snapshot);

    assert_eq!(report.committed, 3);
    assert_eq!(
        msgs.iter().map(|m| m.seq).collect::<Vec<_>>(),
        vec![0, 1, 2]
    );
    assert_eq!(
        msgs.iter()
            .map(|m| m.native_id.as_str())
            .collect::<Vec<_>>(),
        vec!["lifecycle-cx-1", "lifecycle-cx-2", "lifecycle-cx-3"]
    );
    for m in &msgs {
        assert_eq!(m.parent_native_id, None, "线性 rollout 不得产生任何父边");
        assert!(!m.is_sidechain, "codex 无 sidechain 概念");
        assert_eq!(m.timestamp, None, "外层 timestamp 不进稳定字段");
    }
}

#[test]
fn event_msg_mirrors_of_copied_prefix_stay_excluded() {
    // 分叉语料常见的镜像复制：event_msg 与权威 response_item 同文重复。
    // 只有 response_item/message 进索引，镜像绝不成为第二条 occurrence。
    let mirror = json!({
        "timestamp": "2026-07-26T09:00:00.500Z",
        "type": "event_msg",
        "payload": {"type": "user_message", "message": "first rollout message"},
    });
    let snapshot = render(&[session_meta(), m1(), mirror]);
    let (report, msgs) = parse_ok(&snapshot);

    assert_eq!(report.committed, 1, "镜像不得重复计数");
    assert_eq!(msgs.len(), 1);
    assert_eq!(msgs[0].native_id, "lifecycle-cx-1");
}
