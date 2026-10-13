//! Provider 适配器 golden 契约测试的共享脚手架。
//!
//! 每个 `provider-*` crate 的 `tests/golden.rs` 都需要一个全字段捕获 sink、一个从
//! `tests/golden/` 读 fixture + 校验 BLAKE3 指纹的读取器，以及把解析结果投影成
//! canonical JSON 的序列化器。这三者在 14 个适配器里逐字复制，且复制版彼此漂移
//! （早期版本只捕获计数、丢失 native_id/parent/activity）。本模块收口为单一来源，
//! 让新适配器只提供格式特定的 record 提取，golden 测试用例套用同一脚手架。
//!
//! 用法见每个 `provider-*/tests/golden.rs` 迁移后的形态：构造 [`CapturingSink`]，
//! 经 [`parse_golden`] 解析固定 fixture，再由 [`canonical_json`] 投影并与 pinned
//! `basic.expected.json` 比较。

use agent_session_grep_domain::{ToolActivity, UsageObservation};
use agent_session_grep_ports::{
    CanonicalEventSink, MessageEvent, ParseReport, PortResult, ToolActivityEvent, UsageEvent,
};
use serde_json::{Value, json};

/// 全字段捕获 sink：收集所有 `emit_message` + `emit_activity` + `emit_usage` 事件。
///
/// 早期 14 个适配器各自维护 `CollectingSink`/`CountSink`/`RecordingSink`，其中 10 个
/// 只计数（`CountSink`），无法断言 native_id/parent/timestamp/sidechain/span，更无一
/// 个捕获 tool activity。本 sink 捕获全部字段，让每个适配器的 golden 测试能在同一字段
/// 集上断言，也为未来接 `emit_activity` / `emit_usage` 的适配器留好位置。
#[derive(Default)]
pub struct CapturingSink {
    /// 按发出顺序捕获的消息事件（已拥有所有权，脱离输入借用）。
    pub messages: Vec<CapturedMessage>,
    /// 按发出顺序捕获的 tool activity 事件。
    pub activities: Vec<CapturedActivity>,
    /// 按发出顺序捕获的 token usage 事件。
    pub usages: Vec<CapturedUsage>,
}

/// 一条消息事件的所有权快照（`MessageEvent` 借用输入，测试侧需拥有以便断言/序列化）。
#[derive(Debug, Clone)]
pub struct CapturedMessage {
    pub seq: u32,
    pub native_id: String,
    pub parent_native_id: Option<String>,
    pub role: String,
    pub text: String,
    pub timestamp: Option<String>,
    pub is_sidechain: bool,
    pub span: Option<(u64, u64)>,
}

/// 一条 tool activity 事件的所有权快照：锚定消息的 native id + 完整活动事实。
///
/// `ToolActivity` 本身已 `Serialize`，测试可按需断言其字段；此处不重新拍平，避免
/// 与 domain 演进脱节。
#[derive(Debug, Clone)]
pub struct CapturedActivity {
    pub message_native_id: String,
    pub activity: ToolActivity,
}

/// 一条 token usage 事件的所有权快照：锚点 native id（空串 = session 级观察）
/// + 完整用量事实。
#[derive(Debug, Clone)]
pub struct CapturedUsage {
    pub message_native_id: String,
    pub usage: UsageObservation,
}

impl CanonicalEventSink for CapturingSink {
    fn emit_message(&mut self, event: MessageEvent<'_>) -> PortResult<()> {
        self.messages.push(CapturedMessage {
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

    fn emit_activity(&mut self, event: ToolActivityEvent<'_>) -> PortResult<()> {
        self.activities.push(CapturedActivity {
            message_native_id: event.message_native_id.to_string(),
            activity: event.activity.clone(),
        });
        Ok(())
    }

    fn emit_usage(&mut self, event: UsageEvent<'_>) -> PortResult<()> {
        self.usages.push(CapturedUsage {
            message_native_id: event.message_native_id.to_string(),
            usage: event.usage.clone(),
        });
        Ok(())
    }
}

/// 读取 pinned 期望输出（`tests/golden/basic.expected.json`）。
pub fn read_expected(path: &str) -> Value {
    let bytes = std::fs::read(path).expect("read basic.expected.json");
    serde_json::from_slice(&bytes).expect("basic.expected.json must be valid JSON")
}

/// 读 fixture 字节并先校验 BLAKE3 指纹：字节漂移必须先于任何 span/输出失配给出
/// 明确诊断，而不是留下一堆令人困惑的偏移错位。
pub fn read_fixture_verified(fixture_path: &str, expected: &Value) -> Vec<u8> {
    let bytes = std::fs::read(fixture_path).expect("read basic fixture");
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

/// 用给定 adapter 解析 fixture，返回报告与捕获到的事件（消息 + activity）。
///
/// 调用方负责提供具体的 adapter 实例；本函数只做“解析 + 收集”的固定编排。
pub fn parse_golden<A: agent_session_grep_ports::ProviderAdapter>(
    adapter: &A,
    bytes: &[u8],
) -> (ParseReport, CapturingSink) {
    let mut sink = CapturingSink::default();
    let report = adapter
        .parse(bytes, &mut sink)
        .expect("golden fixture parse must succeed");
    (report, sink)
}

/// 把解析结果序列化为 golden 契约约定的 canonical 输出形状，与 pinned
/// `basic.expected.json` 结构对齐（键序无关，serde_json::Value 相等比较）。
///
/// `messages` 的投影与 14 个适配器既有 `canonical_json` 逐字段一致，保证迁移后
/// pinned 文件无需重写。`activities` 不进该投影——既有 expected.json 不含 activities
/// 字段，且只有 claude/codex 会产出 activity，混入会破坏其余 12 个的 pin。
pub fn canonical_json(
    fixture_blake3: &str,
    report: &ParseReport,
    messages: &[CapturedMessage],
) -> Value {
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
