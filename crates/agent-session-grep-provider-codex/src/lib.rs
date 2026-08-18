//! Codex provider adapter：把 Codex CLI 的 rollout JSONL 隔离解析为 Canonical
//! 事件流（落实 RFC-0002 的 probe + parse 职责）。
//!
//! 格式（variant `codex/rollout-jsonl-v1`）：每行一个独立 JSON 对象，统一封套
//! `{"timestamp":..,"type":..,"payload":{..}}`。`type` 取值有 `session_meta` /
//! `event_msg` / `response_item` / `turn_context` / `world_state` 等。
//!
//! **权威对话记录**是 `type:"response_item"` 且 `payload.type:"message"`——它带
//! provider-native `payload.id`、`payload.role`（developer/user/assistant）与
//! `payload.content[]`（block 数组，每块 `{type,text}`）。`event_msg` 的
//! `user_message`/`agent_message` 是同一消息的 UI 镜像（文本重复、无 id），
//! **必须忽略以免重复计数**（真实样本实测：每条对话在两处各出现一次）。
//!
//! 与 Claude Code 的差异：对话字段在 `payload` 封套内（非顶层）；无 `parentUuid`
//! ——Codex rollout 是线性序列，不提供显式 threading 边，故 parent 一律 `None`
//! （诚实：不编造上层可推断的线性链）。外层时间戳是 source occurrence 元数据，
//! 同一 native message 的复制记录可能不同，因此不进入稳定 Message 投影。
//!
//! adapter 只做格式隔离，绝不接触存储 / 检索 / UI（RFC-0002 §7）。

use agent_session_grep_domain::{ToolActivityActor, ToolActivityStatus};
use agent_session_grep_ports::{
    AdapterManifest, CanonicalEventSink, Confidence, MessageEvent, MetadataResolution, ParseReport,
    ProbeResult, ProviderAdapter, ProviderError, ToolActivityEvent, build_tool_activity,
    manifest_for,
};
use serde::{Deserialize, de::IgnoredAny};

/// 本 adapter 认证的 variant 标识。
const VARIANT_ID: &str = "codex/rollout-jsonl-v1";

/// probe 判定用的样本窗口大小（前 N 个非空行，RFC-0002 §7 bounded）。
const SAMPLE_LINE_LIMIT: usize = 16;
/// 样本窗口内容忍的未解析行数上限：≤ 此值只把置信度降一档并继续（解析阶段
/// 对破损行逐行跳过并给出诊断），超过才整源拒绝（PRD R2.1）。
const SAMPLE_BROKEN_TOLERANCE: usize = 3;
/// 拒绝/诊断消息中列出的行号条数上限（bounded detail）。
const BAD_LINE_LIST_LIMIT: usize = 5;
/// 多会话诊断中列出的 session id 条数上限（bounded detail）。
const SESSION_ID_LIST_LIMIT: usize = 3;

// Adapted from claude-historian-mcp/src/parser.ts:74-92 (MIT): inspect cheap
// JSONL markers before invoking serde. Unknown or ambiguous lines remain parse
// candidates so the adapter keeps its existing recoverable-error behavior.
#[derive(Default)]
struct TopLevelMarkers<'a> {
    kind: Option<&'a [u8]>,
    ambiguous: bool,
}

fn json_string_end(line: &[u8], quote: usize) -> Option<(usize, bool)> {
    let mut cursor = quote + 1;
    let mut escaped = false;
    while cursor < line.len() {
        match line[cursor] {
            b'"' => return Some((cursor, escaped)),
            b'\\' => {
                escaped = true;
                cursor = cursor.checked_add(2)?;
            }
            _ => cursor += 1,
        }
    }
    None
}

fn top_level_markers(line: &[u8]) -> TopLevelMarkers<'_> {
    let mut markers = TopLevelMarkers::default();
    let mut cursor = 0usize;
    while line.get(cursor).is_some_and(u8::is_ascii_whitespace) {
        cursor += 1;
    }
    if line.get(cursor) != Some(&b'{') {
        markers.ambiguous = true;
        return markers;
    }

    let mut depth = 1usize;
    cursor += 1;
    while cursor < line.len() && depth > 0 {
        match line[cursor] {
            b'{' | b'[' => {
                depth += 1;
                cursor += 1;
            }
            b'}' | b']' => {
                depth = depth.saturating_sub(1);
                cursor += 1;
            }
            b'"' => {
                let Some((key_end, escaped)) = json_string_end(line, cursor) else {
                    markers.ambiguous = true;
                    break;
                };
                if depth != 1 {
                    cursor = key_end + 1;
                    continue;
                }
                if escaped {
                    markers.ambiguous = true;
                    cursor = key_end + 1;
                    continue;
                }

                let key = &line[cursor + 1..key_end];
                let mut value_cursor = key_end + 1;
                while line.get(value_cursor).is_some_and(u8::is_ascii_whitespace) {
                    value_cursor += 1;
                }
                if line.get(value_cursor) != Some(&b':') {
                    cursor = key_end + 1;
                    continue;
                }
                value_cursor += 1;
                while line.get(value_cursor).is_some_and(u8::is_ascii_whitespace) {
                    value_cursor += 1;
                }

                if key == b"type" {
                    if markers.kind.is_some() {
                        markers.kind = None;
                        markers.ambiguous = true;
                    } else if line.get(value_cursor) == Some(&b'"') {
                        let Some((value_end, value_escaped)) = json_string_end(line, value_cursor)
                        else {
                            markers.ambiguous = true;
                            break;
                        };
                        if value_escaped {
                            markers.ambiguous = true;
                        } else {
                            markers.kind = Some(&line[value_cursor + 1..value_end]);
                        }
                        cursor = value_end + 1;
                        continue;
                    } else {
                        markers.ambiguous = true;
                    }
                }
                cursor = key_end + 1;
            }
            _ => cursor += 1,
        }
    }
    markers
}

fn codex_line_may_need_deserialize(line: &[u8]) -> bool {
    let markers = top_level_markers(line);
    if markers.ambiguous {
        return true;
    }

    const IGNORED_TYPES: [&[u8]; 4] = [b"event_msg", b"turn_context", b"world_state", b"compacted"];
    !markers
        .kind
        .is_some_and(|kind| IGNORED_TYPES.contains(&kind))
}

/// Codex rollout JSONL adapter。无状态——所有解析所需信息都来自输入字节。
///
/// **单文件 = 单会话**：一个源文件预期只含一个会话（`session_meta` 的
/// `session_id`）。若同一文件出现多个不同的 `session_id`（如手工拼接的合并
/// 文件），全部消息仍归属首个出现的会话（保持既有 first-session 契约），
/// 解析报告会追加一条多会话诊断（PRD R3.1）。
#[derive(Debug, Default, Clone, Copy)]
pub struct CodexAdapter;

impl CodexAdapter {
    pub fn new() -> Self {
        CodexAdapter
    }
}

/// 一行 rollout 的最小反序列化视图（统一封套）。
///
/// 只声明判定与抽取所需字段；additive 未知字段被 serde 默认忽略
/// （RFC-0002 §3：additive unknown fields 默认忽略但保留诊断）。
#[derive(Debug, Deserialize)]
struct RawLine {
    /// 外层封套时间戳（ISO-8601 UTC）；仅用于识别 rollout 封套形态。
    ///
    /// 该值属于 source occurrence，同一 native message 的复制记录可能不同，
    /// 因此不能作为稳定 Message 字段。
    #[serde(default)]
    timestamp: Option<String>,
    /// 顶层记录类型（`session_meta` / `event_msg` / `response_item` / …）。
    #[serde(default)]
    r#type: String,
    /// 类型相关的载荷；对话记录才含 role/content。
    #[serde(default)]
    payload: Option<RawPayload>,
}

/// `payload` 的最小视图。因各 `type` 的 payload 结构不同，只声明对话消息
/// （`response_item` + 内层 `message`）与工具调用（`custom_tool_call` /
/// `function_call_output`）所需字段；其它类型缺失这些字段无妨。
#[derive(Debug, Deserialize)]
struct RawPayload {
    /// 内层记录类型（`message` / `reasoning` / `custom_tool_call` / …）。
    #[serde(default)]
    r#type: String,
    /// provider-native 消息 id（`response_item/message` 才有）。
    #[serde(default)]
    id: String,
    /// 角色（`developer` / `user` / `assistant`）。
    #[serde(default)]
    role: String,
    /// Message 的 content-block 数组。非 message 的 response_item（例如
    /// reasoning）可能显式写入 null，必须先按 payload type 分类再解释。
    #[serde(default)]
    content: Option<Vec<RawBlock>>,
    /// durable 会话 id（仅 `session_meta` 的 payload 携带）。
    #[serde(default)]
    session_id: Option<String>,
    /// 会话启动时的工作目录（仅 `session_meta` 的 payload 携带且权威；ADR-0009
    /// Resume metadata 的 Original Working Directory）。`turn_context` 等其它
    /// 类型的 payload 也可能出现 `cwd`，但那是 turn-scoped 状态——解析只在
    /// `session_meta` 分支读取本字段，其它类型的 cwd 绝不作为 working
    /// directory。缺失/空白 → None，绝不臆造。
    #[serde(default)]
    cwd: Option<String>,
    /// `custom_tool_call` 的工具名（如 `shell`）。缺失/空 → 视为不透明调用。
    #[serde(default)]
    name: String,
    /// `custom_tool_call` 的参数：JSON 字符串或对象两种形态都接受
    /// （老版本 rollout 为字符串；新版本直接为对象）。
    #[serde(default)]
    arguments: Option<serde_json::Value>,
    /// `custom_tool_call` 的调用 id（新版本字段；旧版本复用顶层 `id`）。
    #[serde(default, rename = "tool_call_id")]
    tool_call_id: Option<String>,
    /// `function_call_output` 引用的调用 id（与 `custom_tool_call` 配对）。
    #[serde(default, rename = "call_id")]
    call_id: Option<String>,
    /// `function_call_output` 的失败标记；缺失视为 false（成功）。
    #[serde(default, rename = "is_error")]
    is_error: bool,
}

impl RawPayload {
    /// 归一化的调用参数对象：JSON 字符串解析为对象，对象形态原样使用，
    /// 其余（缺失/非对象/解析失败）一律按不透明 `Null` 处理（fail-closed）。
    fn normalized_arguments(&self) -> serde_json::Value {
        match &self.arguments {
            Some(serde_json::Value::String(raw)) => {
                serde_json::from_str(raw).unwrap_or(serde_json::Value::Null)
            }
            Some(value @ serde_json::Value::Object(_)) => value.clone(),
            _ => serde_json::Value::Null,
        }
    }
}

/// 一次尚未配对到结果的工具调用（设计 R5/R6：按 `call_id` 跨记录配对）。
struct PendingToolCall {
    call_id: String,
    name: String,
    input: serde_json::Value,
    /// 发出该调用时最近 emit 的消息 native id（活动锚点，设计 R5.2）。
    anchor: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawBlock {
    /// 仅抽取带 `text` 的 block（如 `input_text` / `output_text`）；
    /// 工具调用等无 text 的 block 被忽略。
    #[serde(default)]
    text: Option<String>,
}

impl RawPayload {
    /// 抽取可检索纯文本；按顺序拼接各 block 的 text。
    fn to_plain_text(&self) -> Option<String> {
        self.content.as_ref().map(|content| {
            content
                .iter()
                .filter_map(|b| b.text.as_deref())
                .collect::<Vec<_>>()
                .join("\n")
        })
    }
}

/// 判定一个角色是否是我们承认的对话角色。
///
/// `developer` 是 Codex 注入的系统提示层（≈ system）；一并保留，让上层按 role
/// 过滤，adapter 不做语义裁剪（RFC-0002 §7：provider 只做格式隔离）。
fn is_conversational_role(role: &str) -> bool {
    matches!(role, "user" | "assistant" | "developer" | "system")
}

/// 把配对好的调用构建为活动并 emit（设计 R2/R3/R4）。
fn emit_paired_activity(
    sink: &mut dyn CanonicalEventSink,
    call: &PendingToolCall,
    is_error: bool,
) -> agent_session_grep_ports::PortResult<()> {
    let activity = build_tool_activity(
        &call.name,
        // Codex rollout 无 sidechain 字段（设计 R3）：一律 Main。
        ToolActivityActor::Main,
        &call.input,
        if is_error {
            ToolActivityStatus::Error
        } else {
            ToolActivityStatus::Success
        },
    );
    sink.emit_activity(ToolActivityEvent {
        message_native_id: call.anchor.as_deref().unwrap_or(""),
        activity,
    })
}

/// 未配对调用在文件末尾以 `Unknown` 状态如实上报（设计 R4.3），绝不臆造结果。
fn emit_unpaired_activity(
    sink: &mut dyn CanonicalEventSink,
    call: &PendingToolCall,
) -> agent_session_grep_ports::PortResult<()> {
    let activity = build_tool_activity(
        &call.name,
        ToolActivityActor::Main,
        &call.input,
        ToolActivityStatus::Unknown,
    );
    sink.emit_activity(ToolActivityEvent {
        message_native_id: call.anchor.as_deref().unwrap_or(""),
        activity,
    })
}

/// Codex 已知的顶层封套类型——probe 判定用。
fn is_known_envelope_type(kind: &str) -> bool {
    matches!(
        kind,
        "session_meta"
            | "event_msg"
            | "response_item"
            | "turn_context"
            | "world_state"
            | "compacted"
    )
}

/// 把行号序列格式化为中文定位列表；超过上限用"等 N 处"收口（bounded detail）。
fn list_line_nos(nos: &[usize]) -> String {
    let mut out = String::new();
    let shown = nos.len().min(BAD_LINE_LIST_LIMIT);
    for (i, no) in nos[..shown].iter().enumerate() {
        if i > 0 {
            out.push('、');
        }
        out.push_str(&no.to_string());
    }
    if nos.len() > shown {
        out.push_str(&format!(" 等 {} 处", nos.len()));
    }
    out
}

/// 整源拒绝时的行号定位 + 修复方向（PRD R2.2）：绝不裸报 "no provider
/// recognized"。
fn bad_lines_detail(bad_lines: &[usize]) -> String {
    format!(
        "第 {} 行不是有效 JSON。请修复或删除这些行后重试（该文件应为每行一条 JSON 封套记录的 Codex rollout JSONL）",
        list_line_nos(bad_lines)
    )
}

impl ProviderAdapter for CodexAdapter {
    fn provider_id(&self) -> &str {
        "codex"
    }

    fn manifest(&self) -> AdapterManifest {
        manifest_for(
            self.provider_id(),
            Some(1),
            &[
                "tool activity extraction is partial",
                "turn_context metadata is not surfaced as canonical messages",
            ],
        )
    }

    fn probe(&self, bytes: &[u8]) -> Result<ProbeResult, ProviderError> {
        let text = std::str::from_utf8(bytes)
            .map_err(|e| ProviderError::StructuralFatal(format!("not valid UTF-8: {e}")))?;
        // UTF-8 BOM（Windows 编辑器常见）不属于 JSON 语法：先剥离再逐行判定。
        let text = text.strip_prefix('\u{feff}').unwrap_or(text);

        let mut matched = Vec::new();
        let mut unmatched = Vec::new();

        // 取前若干非空行做判定，避免整体加载（RFC-0002 §7 bounded）；同时保留
        // 原始行号，供容忍/拒绝路径给出"第 N 行"的准确定位。
        let mut sample: Vec<(usize, &str)> = Vec::new();
        for (idx, line) in text.lines().enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            if sample.len() == SAMPLE_LINE_LIMIT {
                break;
            }
            sample.push((idx + 1, line));
        }

        if sample.is_empty() {
            return Err(ProviderError::AmbiguousVariant(
                "empty input: no non-blank lines to probe；请确认该文件不是空文件，且是 Codex CLI 的 rollout JSONL"
                    .into(),
            ));
        }

        let mut json_lines = 0usize;
        let mut enveloped = 0usize;
        let mut timestamped = 0usize;
        let mut has_session_meta = false;
        let mut has_message = false;
        let mut bad_lines: Vec<usize> = Vec::new();
        for &(line_no, line) in &sample {
            match serde_json::from_str::<RawLine>(line) {
                Ok(rec) => {
                    json_lines += 1;
                    // Codex 封套的正信号：payload 存在 + type 属于已知集合。
                    if rec.payload.is_some() && is_known_envelope_type(&rec.r#type) {
                        enveloped += 1;
                        if rec.timestamp.is_some() {
                            timestamped += 1;
                        }
                    }
                    if rec.r#type == "session_meta" {
                        has_session_meta = true;
                    }
                    if rec.r#type == "response_item"
                        && rec.payload.as_ref().map(|p| p.r#type.as_str()) == Some("message")
                    {
                        has_message = true;
                    }
                }
                Err(_) => {
                    bad_lines.push(line_no);
                    unmatched.push(format!("line {line_no}: found a non-JSON line"));
                }
            }
        }

        // 样本内少量未解析行（≤ 容忍度且至少有一行可解析）不是整源拒绝的理由：
        // 降一档置信度继续——解析阶段会对这些行逐行跳过并给出诊断（PRD R2.1）。
        // 超过容忍度，或一行都没解析出来（整文件是垃圾而非"带破损行的 rollout"）
        // → 整源拒绝，错误携带行号定位与修复方向（PRD R2.2）。
        if !bad_lines.is_empty() {
            if bad_lines.len() > SAMPLE_BROKEN_TOLERANCE || json_lines == 0 {
                return Err(ProviderError::AmbiguousVariant(format!(
                    "not line-delimited JSON: {}/{} sampled lines parsed。{}",
                    json_lines,
                    sample.len(),
                    bad_lines_detail(&bad_lines)
                )));
            }
            unmatched.push(format!(
                "第 {} 行未解析——在样本容忍度内（≤{SAMPLE_BROKEN_TOLERANCE}），置信度降一档",
                list_line_nos(&bad_lines)
            ));
        }
        matched.push(format!("{json_lines} sampled lines are valid JSON objects"));

        // 无任何 Codex 封套结构 → 不是本 variant（可能是别的 JSONL，如 Claude Code）。
        if enveloped == 0 {
            return Err(ProviderError::AmbiguousVariant(
                "no Codex envelope records ({timestamp,type,payload}) found；该文件可能不是 Codex CLI 的 rollout JSONL，请确认来源文件"
                    .into(),
            ));
        }
        matched.push(format!("{enveloped} lines carry a Codex envelope"));
        if timestamped > 0 {
            matched.push(format!(
                "{timestamped} Codex envelopes carry an outer occurrence timestamp"
            ));
        }

        // 收紧正信号：单条封套行不足以 Confirmed——至少 2 条封套行（其余行已由
        // 全量可解析门保证）且出现会话头或权威对话记录才承诺 Confirmed。
        let mut confidence = if enveloped >= 2 && (has_session_meta || has_message) {
            if has_session_meta {
                matched.push("session_meta header present".into());
            }
            if has_message {
                matched.push("response_item/message records present".into());
            }
            Confidence::Confirmed
        } else if has_session_meta || has_message {
            unmatched.push(format!(
                "only {enveloped} envelope line(s) in sample — too few to confirm"
            ));
            Confidence::High
        } else {
            unmatched.push("no session_meta or response_item/message in sample".into());
            Confidence::High
        };

        // 容忍路径：置信度降一档（Low 不再降——Ambiguous 是拒绝语义，本路径保持认领）。
        if !bad_lines.is_empty() {
            confidence = match confidence {
                Confidence::Confirmed => {
                    matched.push("confidence degraded to High (tolerated broken lines)".into());
                    Confidence::High
                }
                Confidence::High => {
                    matched.push("confidence degraded to Low (tolerated broken lines)".into());
                    Confidence::Low
                }
                other => other,
            };
        }

        Ok(ProbeResult {
            variant_id: VARIANT_ID.to_string(),
            confidence,
            matched_evidence: matched,
            unmatched_evidence: unmatched,
        })
    }

    fn parse(
        &self,
        bytes: &[u8],
        sink: &mut dyn CanonicalEventSink,
    ) -> Result<ParseReport, ProviderError> {
        // 字节兼容路径：把整段字节包成只读切片源，与生产流式路径共用同一实现。
        let source = agent_session_grep_ports::SliceSource::new(bytes);
        self.parse_source(&source, sink)
    }

    fn parse_source(
        &self,
        source: &dyn agent_session_grep_ports::ReadOnlySource,
        sink: &mut dyn CanonicalEventSink,
    ) -> Result<ParseReport, ProviderError> {
        // 流式逐行读取：内存上界是单条记录（manifest max_record_size），
        // 不是文件大小（RFC-0002 §7）。
        let mut lines = agent_session_grep_ports::BoundedLineReader::new(
            source,
            agent_session_grep_ports::STREAM_RECORD_MAX_BYTES,
        )
        .map_err(|e| ProviderError::Io(e.to_string()))?;

        let mut report = ParseReport::default();
        // 本文件出现的全部非空 session id（单文件=单会话契约的检测输入）。
        let mut session_ids: Vec<String> = Vec::new();
        // seq 是会话内单调序号，只对成功 emit 的对话消息递增，
        // 从而满足 domain Session 的 seq 从 0 连续的不变量。
        let mut seq: u32 = 0;
        // 工具活动观察（设计 R1-R6）：按 `call_id` 跨记录配对的待决调用。
        let mut pending_calls: Vec<PendingToolCall> = Vec::new();
        // 最近一次成功 emit 的消息 native id——custom_tool_call 的活动锚点
        // （设计 R5.2：Codex 无显式 call→message 指针，取发出调用的助理消息）。
        let mut last_emitted_native_id: Option<String> = None;

        while let Some(line) = lines.next_record()? {
            // 行负载已由 BoundedLineReader 剥离 \n/\r 与首行 BOM，span 仍以
            // 快照字节为坐标系（start/end 与整段 parse 逐字节一致）。
            let parse_line = std::str::from_utf8(line.bytes)
                .map_err(|e| ProviderError::StructuralFatal(format!("not valid UTF-8: {e}")))?;
            let line_no = line.number - 1;
            let start = line.start;
            let end = line.end;
            if parse_line.trim().is_empty() {
                continue;
            }
            // Prefilter (adapted from claude-historian-mcp, MIT): skip
            // deserialization for records whose type marker is a known
            // non-conversational, non-session-bearing envelope. Conservative:
            // unknown/ambiguous records fall through to serde.
            if !codex_line_may_need_deserialize(parse_line.as_bytes())
                && serde_json::from_str::<IgnoredAny>(parse_line).is_ok()
            {
                continue;
            }
            let rec: RawLine = match serde_json::from_str(parse_line) {
                Ok(r) => r,
                Err(e) => {
                    // 单行 JSON 破损属于 record_recoverable：跳过并标记，不整体失败。
                    report.skipped += 1;
                    report
                        .diagnostics
                        .push(format!("line {}: invalid JSON, skipped ({e})", line_no + 1));
                    continue;
                }
            };

            // session_meta 头携带 durable 会话 id——上报后该行不产生 Canonical 消息；
            // 同时收集全部非空 session id，供末尾的多会话诊断（PRD R3.1）。
            if rec.r#type == "session_meta" {
                if let Some(sid) = rec.payload.as_ref().and_then(|p| p.session_id.as_deref())
                    && !sid.trim().is_empty()
                {
                    let sid = sid.trim();
                    if report.session_native_id.is_none() {
                        report.session_native_id = Some(sid.to_string());
                    }
                    if !session_ids.iter().any(|s| s == sid) {
                        session_ids.push(sid.to_string());
                    }
                    // Resume metadata（ADR-0009）：provider_session_id 取首个非空
                    // session_id；只有 sid 无 cwd 时目录保持 Missing（显式缺失不臆造）。
                    if report.session_observation.provider_session_id == MetadataResolution::Missing
                    {
                        report.session_observation.provider_session_id =
                            MetadataResolution::Resolved(sid.to_string());
                    }
                    // Original Working Directory 只从「同一条 session_meta
                    // payload 同时携带非空 session_id 与 cwd」的首个 pair 观测，
                    // 且该 pair 必须属于首个会话——其它会话的 cwd 绝不拼接
                    // （R3 保关联）。turn_context 的 cwd 是 turn-scoped，绝不
                    // 作为 working directory（见 RawPayload::cwd 注释）。
                    if !report.session_observation.pair_observed
                        && report.session_native_id.as_deref() == Some(sid)
                        && let Some(cwd) = rec.payload.as_ref().and_then(|p| p.cwd.as_deref())
                        && !cwd.trim().is_empty()
                    {
                        report.session_observation.original_working_directory =
                            MetadataResolution::Resolved(cwd.trim().to_string());
                        report.session_observation.pair_observed = true;
                    }
                }
                continue;
            }

            // 只认权威对话记录：response_item + 内层 message。event_msg 的对话镜像
            // （user_message/agent_message）在此被静默略过，避免同一消息重复计数。
            if rec.r#type != "response_item" {
                continue;
            }
            let Some(payload) = rec.payload else {
                continue;
            };
            // 工具活动观察（设计 R1-R6）：custom_tool_call 登记待决调用；
            // function_call_output 配对后 emit。两者都不是对话消息记录。
            if payload.r#type == "custom_tool_call" {
                let call_id = payload
                    .tool_call_id
                    .clone()
                    .or_else(|| {
                        if payload.id.trim().is_empty() {
                            None
                        } else {
                            Some(payload.id.clone())
                        }
                    })
                    .filter(|id| !id.trim().is_empty());
                if let (Some(call_id), name) = (call_id, payload.name.trim())
                    && !name.is_empty()
                {
                    pending_calls.push(PendingToolCall {
                        call_id,
                        name: name.to_string(),
                        input: payload.normalized_arguments(),
                        anchor: last_emitted_native_id.clone(),
                    });
                }
                // 缺 call id 或 name 的调用视为不透明（R6），静默跳过。
                continue;
            }
            if payload.r#type == "function_call_output" {
                if let Some(call_id) = payload.call_id.as_deref()
                    && let Some(index) = pending_calls
                        .iter()
                        .position(|call| call.call_id == *call_id)
                {
                    let call = pending_calls.remove(index);
                    emit_paired_activity(sink, &call, payload.is_error)
                        .map_err(|e| ProviderError::StructuralFatal(e.to_string()))?;
                }
                // 无匹配 call_id 的输出视为不透明（R6），静默跳过。
                continue;
            }
            if payload.r#type != "message" {
                continue;
            }
            if !is_conversational_role(&payload.role) {
                // An authoritative conversation occurrence with an unknown or
                // empty role cannot be emitted; count it as a recoverable skip
                // like the null-content path below, never silently.
                report.skipped += 1;
                report.diagnostics.push(format!(
                    "line {}: response message with unknown role {:?}, skipped",
                    line_no + 1,
                    payload.role
                ));
                continue;
            }

            let Some(body) = payload.to_plain_text() else {
                report.skipped += 1;
                report.diagnostics.push(format!(
                    "line {}: response message without content array, skipped",
                    line_no + 1
                ));
                continue;
            };

            sink.emit_message(MessageEvent {
                seq,
                native_id: &payload.id,
                // Codex rollout 不提供显式父指针，线性序列的 threading 由上层推断。
                parent_native_id: None,
                role: &payload.role,
                text: &body,
                // The outer envelope timestamp is occurrence-local. Real
                // cross-source copies retain one native id and stable content
                // while carrying different envelope timestamps, so no stable
                // provider timestamp exists for this Message entity.
                timestamp: None,
                is_sidechain: false,
                // 该消息来源封套行在快照字节中的区间（end 排他，不含换行）。
                span: Some((start, end)),
            })
            .map_err(|e| ProviderError::StructuralFatal(e.to_string()))?;
            seq += 1;
            report.committed += 1;
            if !payload.id.trim().is_empty() {
                last_emitted_native_id = Some(payload.id.clone());
            }
        }

        // 文件末尾仍未配对的调用：以 Unknown 状态如实上报（设计 R4.3）。
        for call in &pending_calls {
            emit_unpaired_activity(sink, call)
                .map_err(|e| ProviderError::StructuralFatal(e.to_string()))?;
        }

        // 多会话诊断（PRD R3.1）：单文件=单会话。同一文件出现多个不同 session id
        // 时不得静默折叠——报告数量与前若干 id，归属保持首个会话不变。
        if session_ids.len() > 1 {
            // Resume metadata 的 typed 映射（ADR-0009）：Source 携带多个不同
            // Session ID → fail closed——multi_session 置位，且不把首条 id 当
            // 权威 Resume 声明（provider_session_id 置 Ambiguous）；目录保持
            // 已观测 pair 值或 Missing，由上层按 multi_session 判定不可恢复。
            report.session_observation.multi_session = true;
            report.session_observation.provider_session_id = MetadataResolution::Ambiguous;
            let mut id_list = session_ids
                .iter()
                .take(SESSION_ID_LIST_LIMIT)
                .cloned()
                .collect::<Vec<_>>()
                .join("、");
            if session_ids.len() > SESSION_ID_LIST_LIMIT {
                id_list.push_str(" 等");
            }
            report.diagnostics.push(format!(
                "文件包含 {} 个不同 session id（{}）——单文件=单会话，全部消息归属首个会话 {}",
                session_ids.len(),
                id_list,
                session_ids[0]
            ));
        }

        Ok(report)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_session_grep_domain::{ToolActivity, ToolActivityKind};

    #[test]
    fn manifest_matches_provider_matrix() {
        let adapter = CodexAdapter::new();
        let manifest = adapter.manifest();
        assert_eq!(manifest.provider_id, adapter.provider_id());
        assert_eq!(manifest.supported_variants, vec![VARIANT_ID.to_string()]);
        assert_eq!(manifest.capabilities.provider_id, adapter.provider_id());
        assert_eq!(manifest.capabilities.variant_id, VARIANT_ID);
        assert!(manifest.last_certified_targets.is_empty());
        assert_eq!(manifest.fixture_revision, Some(1));
    }

    /// 收集 emit 的消息事件，供断言解析结果（含 native 身份/时间）。
    #[derive(Default)]
    struct CollectingSink {
        messages: Vec<Captured>,
        activities: Vec<CapturedActivity>,
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
    /// 拍平的活动快照（anchor + 完整事实）。
    struct CapturedActivity {
        message_native_id: String,
        activity: ToolActivity,
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

        fn emit_activity(
            &mut self,
            event: ToolActivityEvent<'_>,
        ) -> agent_session_grep_ports::PortResult<()> {
            self.activities.push(CapturedActivity {
                message_native_id: event.message_native_id.to_string(),
                activity: event.activity,
            });
            Ok(())
        }
    }

    // 合成的 Codex rollout 片段（按 R0 脱敏规范，非真实 transcript）：
    // session_meta 头 + 一条 event_msg 对话镜像 + 两条权威 response_item/message。
    // 关键：user 消息在 event_msg 与 response_item 各出现一次，adapter 只应计一次。
    const SAMPLE: &str = r#"{"timestamp":"2026-07-19T23:40:00.000Z","type":"session_meta","payload":{"session_id":"019f7b08","cwd":"/tmp"}}
{"timestamp":"2026-07-19T23:40:01.000Z","type":"event_msg","payload":{"type":"user_message","message":"how do I configure the sandbox"}}
{"timestamp":"2026-07-19T23:40:01.000Z","type":"response_item","payload":{"type":"message","id":"msg_u1","role":"user","content":[{"type":"input_text","text":"how do I configure the sandbox"}]}}
{"timestamp":"2026-07-19T23:40:02.500Z","type":"response_item","payload":{"type":"message","id":"msg_a1","role":"assistant","content":[{"type":"output_text","text":"set the policy"},{"type":"output_text","text":"in config.toml"}]}}
{"timestamp":"2026-07-19T23:40:02.000Z","type":"response_item","payload":{"type":"reasoning","id":"rs_1","summary":[]}}"#;

    #[test]
    fn probe_confirms_codex_rollout() {
        let r = CodexAdapter::new().probe(SAMPLE.as_bytes()).unwrap();
        assert_eq!(r.variant_id, VARIANT_ID);
        assert_eq!(r.confidence, Confidence::Confirmed);
    }

    #[test]
    fn probe_rejects_non_jsonl() {
        let err = CodexAdapter::new()
            .probe(b"this is not json\nnor is this")
            .unwrap_err();
        assert!(matches!(err, ProviderError::AmbiguousVariant(_)));
    }

    #[test]
    fn probe_rejects_empty() {
        let err = CodexAdapter::new().probe(b"   \n  \n").unwrap_err();
        assert!(matches!(err, ProviderError::AmbiguousVariant(_)));
    }

    #[test]
    fn probe_rejects_claude_code_jsonl() {
        // Claude Code 行无 payload 封套——本 adapter 必须拒绝，不越界解析。
        let claude = r#"{"type":"user","uuid":"u-1","message":{"role":"user","content":"hi"}}
{"type":"assistant","uuid":"a-1","message":{"role":"assistant","content":"yo"}}"#;
        let err = CodexAdapter::new().probe(claude.as_bytes()).unwrap_err();
        assert!(matches!(err, ProviderError::AmbiguousVariant(_)));
    }

    #[test]
    fn probe_tolerates_broken_line_within_tolerance() {
        // 1 条非 JSON 行 ≤ 容忍度（3）：不整源拒绝，置信度降一档
        // （无破损时为 Confirmed → High），并保留 tolerance 证据（PRD R2.1）。
        let mut lines: Vec<&str> = SAMPLE.lines().collect();
        lines.insert(1, "this is not json");
        let input = lines.join("\n");
        let r = CodexAdapter::new().probe(input.as_bytes()).unwrap();
        assert_eq!(r.confidence, Confidence::High);
        assert!(
            r.unmatched_evidence.iter().any(|e| e.contains("容忍")),
            "unmatched evidence 应说明容忍降档: {:?}",
            r.unmatched_evidence
        );
    }

    #[test]
    fn probe_tolerates_up_to_three_broken_lines() {
        // 恰好 3 条破损行 + 至少一条可解析行 → 仍在容忍度内，不拒绝。
        let mut lines: Vec<&str> = SAMPLE.lines().collect();
        lines.insert(1, "bad one");
        lines.insert(1, "bad two");
        lines.insert(1, "bad three");
        let input = lines.join("\n");
        let r = CodexAdapter::new().probe(input.as_bytes()).unwrap();
        assert_eq!(r.confidence, Confidence::High); // would-be Confirmed → High
    }

    #[test]
    fn probe_rejects_broken_lines_beyond_tolerance_with_line_numbers() {
        // 破损行数超过容忍度（4 > 3）：整源拒绝，错误携带"第 N 行"定位
        // 与修复方向（PRD R2.2），绝不裸报。
        let input = concat!(
            "bad one\n",
            "bad two\n",
            "bad three\n",
            "bad four\n",
            "{\"timestamp\":\"t\",\"type\":\"session_meta\",\"payload\":{\"session_id\":\"s-1\"}}",
        );
        let err = CodexAdapter::new().probe(input.as_bytes()).unwrap_err();
        let ProviderError::AmbiguousVariant(msg) = &err else {
            panic!("expected AmbiguousVariant, got {err:?}");
        };
        assert!(msg.contains("第 1、2、3、4 行"), "应列出破损行号: {msg}");
        assert!(
            msg.contains("修复") && msg.contains("重试"),
            "应给出修复方向: {msg}"
        );
    }

    #[test]
    fn parse_reports_multi_session_diagnostic_and_keeps_first_session() {
        // 两个 session_meta 头带不同 session_id（手工拼接的合并文件）：不静默
        // 折叠——产出诊断（数量 + id），归属仍为首个会话（PRD R3.1）。
        let meta = SAMPLE.lines().next().unwrap();
        let first = meta.replace("019f7b08", "sess-first");
        let second = meta.replace("019f7b08", "sess-second");
        let input = format!("{first}\n{second}\n{}", SAMPLE.lines().nth(2).unwrap());
        let mut sink = CollectingSink::default();
        let report = CodexAdapter::new()
            .parse(input.as_bytes(), &mut sink)
            .unwrap();
        assert_eq!(report.session_native_id.as_deref(), Some("sess-first"));
        assert_eq!(report.committed, 1);
        let diag = report
            .diagnostics
            .iter()
            .find(|d| d.contains("不同 session id"))
            .expect("must emit a multi-session diagnostic");
        assert!(diag.contains('2'), "诊断应含会话数量: {diag}");
        assert!(
            diag.contains("sess-first") && diag.contains("sess-second"),
            "诊断应含会话 id: {diag}"
        );
    }

    #[test]
    fn parse_single_session_emits_no_multi_session_diagnostic() {
        let mut sink = CollectingSink::default();
        let report = CodexAdapter::new()
            .parse(SAMPLE.as_bytes(), &mut sink)
            .unwrap();
        assert!(report.session_native_id.is_some());
        assert!(
            !report
                .diagnostics
                .iter()
                .any(|d| d.contains("不同 session id")),
            "单会话文件不得产生多会话诊断: {:?}",
            report.diagnostics
        );
    }

    #[test]
    fn probe_single_envelope_line_is_high_not_confirmed() {
        // 收紧正信号：单条封套行（如只有 session_meta）不足以 Confirmed。
        let input = r#"{"timestamp":"2026-07-19T15:40:00.000Z","type":"session_meta","payload":{"session_id":"s-1"}}"#;
        let r = CodexAdapter::new().probe(input.as_bytes()).unwrap();
        assert_eq!(r.confidence, Confidence::High);
    }

    #[test]
    fn probe_two_envelope_lines_confirms() {
        // 两条封套行（会话头 + 权威消息）即确认——与 provider_matrix 的最小样本一致。
        let input = concat!(
            r#"{"timestamp":"2026-07-19T15:40:00.000Z","type":"session_meta","payload":{"session_id":"s-1"}}"#,
            "\n",
            r#"{"timestamp":"2026-07-19T15:41:00.000Z","type":"response_item","payload":{"type":"message","id":"m-1","role":"user","content":[{"type":"input_text","text":"hi"}]}}"#,
        );
        let r = CodexAdapter::new().probe(input.as_bytes()).unwrap();
        assert_eq!(r.confidence, Confidence::Confirmed);
    }

    #[test]
    fn probe_accepts_utf8_bom_prefix() {
        // Windows 编辑器可能给文件加 UTF-8 BOM：probe 必须先剥离再判定。
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"\xEF\xBB\xBF");
        bytes.extend_from_slice(SAMPLE.as_bytes());
        let r = CodexAdapter::new().probe(&bytes).unwrap();
        assert_eq!(r.confidence, Confidence::Confirmed);
    }

    #[test]
    fn parse_takes_authoritative_message_ignores_event_mirror() {
        let mut sink = CollectingSink::default();
        let report = CodexAdapter::new()
            .parse(SAMPLE.as_bytes(), &mut sink)
            .unwrap();
        // 只有两条 response_item/message 被提交：event_msg 镜像与 reasoning 被略过。
        assert_eq!(report.committed, 2);
        assert_eq!(sink.messages.len(), 2);
        // seq 从 0 连续。
        assert_eq!(sink.messages[0].seq, 0);
        assert_eq!(sink.messages[1].seq, 1);
        // native id 原样透传。
        assert_eq!(sink.messages[0].native_id, "msg_u1");
        assert_eq!(sink.messages[1].native_id, "msg_a1");
        // role 原样透传。
        assert_eq!(sink.messages[0].role, "user");
        assert_eq!(sink.messages[1].role, "assistant");
        // content block 数组按序拼接。
        assert_eq!(sink.messages[0].text, "how do I configure the sandbox");
        assert_eq!(sink.messages[1].text, "set the policy\nin config.toml");
        // 外层封套时间戳属于 source occurrence，不进入稳定 Message。
        assert_eq!(sink.messages[0].timestamp, None);
        // Codex 无显式父指针 / sidechain。
        assert_eq!(sink.messages[0].parent_native_id, None);
        assert!(!sink.messages[0].is_sidechain);
    }

    #[test]
    fn parse_ignores_reasoning_with_null_content_without_skip() {
        let input = br#"{"timestamp":"2026-07-19T23:40:02.000Z","type":"response_item","payload":{"type":"reasoning","id":"rs-null","content":null}}
{"timestamp":"2026-07-19T23:40:03.000Z","type":"response_item","payload":{"type":"message","id":"msg-kept","role":"assistant","content":[{"type":"output_text","text":"kept"}]}}"#;
        let mut sink = CollectingSink::default();
        let report = CodexAdapter::new()
            .parse(input, &mut sink)
            .expect("parse synthetic rollout");

        assert_eq!(report.committed, 1);
        assert_eq!(report.skipped, 0);
        assert!(report.diagnostics.is_empty());
        assert_eq!(sink.messages.len(), 1);
        assert_eq!(sink.messages[0].text, "kept");
    }

    #[test]
    fn parse_skips_message_with_null_content_recoverably() {
        let input = br#"{"timestamp":"2026-07-19T23:40:02.000Z","type":"response_item","payload":{"type":"message","id":"msg-null","role":"assistant","content":null}}"#;
        let mut sink = CollectingSink::default();
        let report = CodexAdapter::new()
            .parse(input, &mut sink)
            .expect("parse synthetic rollout");

        assert_eq!(report.committed, 0);
        assert_eq!(report.skipped, 1);
        assert_eq!(report.diagnostics.len(), 1);
        assert!(sink.messages.is_empty());
    }

    #[test]
    fn parse_skips_message_with_unknown_role_recoverably() {
        let input = br#"{"timestamp":"2026-07-19T23:40:02.000Z","type":"response_item","payload":{"type":"message","id":"msg-role","role":"function","content":[{"type":"input_text","text":"hi"}]}}"#;
        let mut sink = CollectingSink::default();
        let report = CodexAdapter::new()
            .parse(input, &mut sink)
            .expect("parse synthetic rollout");

        assert_eq!(report.committed, 0);
        assert_eq!(
            report.skipped, 1,
            "unknown role must count as a recoverable skip"
        );
        assert_eq!(report.diagnostics.len(), 1);
        assert!(sink.messages.is_empty());
    }

    fn parse_single_message(timestamp: &str, role: &str, text: &str) -> Captured {
        let input = serde_json::to_vec(&serde_json::json!({
            "timestamp": timestamp,
            "type": "response_item",
            "payload": {
                "type": "message",
                "id": "shared-synthetic-id",
                "role": role,
                "content": [{"type": "input_text", "text": text}],
            },
        }))
        .expect("serialize synthetic rollout");
        let mut sink = CollectingSink::default();
        CodexAdapter::new()
            .parse(&input, &mut sink)
            .expect("parse synthetic rollout");
        assert_eq!(sink.messages.len(), 1);
        sink.messages.remove(0)
    }

    #[test]
    fn parse_keeps_stable_projection_equal_across_occurrence_timestamps() {
        let first = parse_single_message(
            "2026-07-19T23:40:01.000Z",
            "user",
            "stable synthetic content",
        );
        let copied = parse_single_message(
            "2026-07-20T10:15:30.000Z",
            "user",
            "stable synthetic content",
        );

        assert_eq!(first.native_id, copied.native_id);
        assert_eq!(first.role, copied.role);
        assert_eq!(first.text, copied.text);
        assert_eq!(first.timestamp, None);
        assert_eq!(copied.timestamp, None);
    }

    #[test]
    fn parse_preserves_genuine_role_and_text_differences() {
        let first = parse_single_message(
            "2026-07-19T23:40:01.000Z",
            "user",
            "first synthetic content",
        );
        let changed = parse_single_message(
            "2026-07-20T10:15:30.000Z",
            "assistant",
            "changed synthetic content",
        );

        assert_eq!(first.native_id, changed.native_id);
        assert_ne!((first.role, first.text), (changed.role, changed.text));
        assert_eq!(first.timestamp, None);
        assert_eq!(changed.timestamp, None);
    }

    #[test]
    fn parse_skips_broken_line_recoverably() {
        let input = "{\"timestamp\":\"t\",\"type\":\"response_item\",\"payload\":{\"type\":\"message\",\"id\":\"m1\",\"role\":\"user\",\"content\":[{\"type\":\"input_text\",\"text\":\"ok\"}]}}\n{not valid json}";
        let mut sink = CollectingSink::default();
        let report = CodexAdapter::new()
            .parse(input.as_bytes(), &mut sink)
            .unwrap();
        assert_eq!(report.committed, 1);
        assert_eq!(report.skipped, 1);
        assert_eq!(report.diagnostics.len(), 1);
    }

    #[test]
    fn parse_accepts_utf8_bom_prefix() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"\xEF\xBB\xBF");
        bytes.extend_from_slice(SAMPLE.as_bytes());
        let mut sink = CollectingSink::default();
        let report = CodexAdapter::new().parse(&bytes, &mut sink).unwrap();
        // BOM 不改变解析结果：session_meta 首行正常解析，不产生假 skip。
        assert_eq!(report.committed, 2);
        assert_eq!(report.skipped, 0);
        assert_eq!(sink.messages.len(), 2);
        // span 仍以快照字节为坐标系：BOM 属于首行，首条权威消息（第 2 行，0 基）
        // 的 span 起点 = BOM(3) + 前两行（含换行）的字节数；切片不含 BOM。
        let bom_len = 3u64;
        let prefix: u64 = SAMPLE.lines().take(2).map(|l| l.len() as u64 + 1).sum();
        let (start, end) = sink.messages[0].span.expect("span required");
        assert_eq!(start, bom_len + prefix);
        assert_eq!(
            &bytes[start as usize..end as usize],
            SAMPLE.lines().nth(2).unwrap().as_bytes()
        );
    }

    #[test]
    fn parse_reports_span_roundtripping_to_source_line() {
        let bytes = SAMPLE.as_bytes();
        let mut sink = CollectingSink::default();
        CodexAdapter::new().parse(bytes, &mut sink).unwrap();
        // 每条消息的 span 切回快照字节，必须精确等于其来源封套行。
        let lines: Vec<&str> = SAMPLE.lines().collect();
        // 两条权威消息分别来自第 3、4 行（0 基：2、3）。
        for (captured, expected_line) in sink.messages.iter().zip([lines[2], lines[3]]) {
            let (start, end) = captured.span.expect("provider must report a span");
            assert_eq!(
                &bytes[start as usize..end as usize],
                expected_line.as_bytes()
            );
        }
    }

    #[test]
    fn parse_reports_span_roundtripping_on_crlf_lines() {
        // Windows CRLF rollout：span 不含 `\r`/`\n`，切回快照字节等于记录正文。
        let line = r#"{"timestamp":"2026-07-19T15:41:00.000Z","type":"response_item","payload":{"type":"message","id":"crlf-1","role":"user","content":[{"type":"input_text","text":"crlf span"}]}}"#;
        let bytes = format!("{line}\r\n").into_bytes();
        let mut sink = CollectingSink::default();
        CodexAdapter::new().parse(&bytes, &mut sink).unwrap();
        assert_eq!(sink.messages.len(), 1);
        let (start, end) = sink.messages[0].span.expect("span required");
        assert_eq!(&bytes[start as usize..end as usize], line.as_bytes());
        // end 排他：下一字节是 `\r`（CRLF 的 CR），不在 span 内。
        assert_eq!(bytes[end as usize], b'\r');
    }

    #[test]
    fn parse_surfaces_session_native_id_from_session_meta() {
        let mut sink = CollectingSink::default();
        let report = CodexAdapter::new()
            .parse(SAMPLE.as_bytes(), &mut sink)
            .unwrap();
        assert_eq!(report.session_native_id.as_deref(), Some("019f7b08"));
        // session_meta 行本身不产生消息，镜像忽略行为不变。
        assert_eq!(report.committed, 2);
    }

    #[test]
    fn parse_without_session_meta_reports_none() {
        let input = "{\"timestamp\":\"t\",\"type\":\"response_item\",\"payload\":{\"type\":\"message\",\"id\":\"m1\",\"role\":\"user\",\"content\":[{\"type\":\"input_text\",\"text\":\"ok\"}]}}";
        let mut sink = CollectingSink::default();
        let report = CodexAdapter::new()
            .parse(input.as_bytes(), &mut sink)
            .unwrap();
        // 无 session_meta → None，显式缺失不臆造。
        assert_eq!(report.session_native_id, None);
    }

    #[test]
    fn parse_observation_reports_pair_from_session_meta() {
        // SAMPLE 的 session_meta payload 同时携带 session_id 与 cwd → pair
        // 关联被捕获（R3 保关联：两值来自同一条权威 payload）。
        let mut sink = CollectingSink::default();
        let report = CodexAdapter::new()
            .parse(SAMPLE.as_bytes(), &mut sink)
            .unwrap();
        let obs = &report.session_observation;
        assert_eq!(
            obs.provider_session_id,
            MetadataResolution::Resolved("019f7b08".to_string())
        );
        assert_eq!(
            obs.original_working_directory,
            MetadataResolution::Resolved("/tmp".to_string())
        );
        assert!(obs.pair_observed);
        assert!(!obs.multi_session);
    }

    #[test]
    fn parse_observation_sid_only_keeps_directory_missing() {
        // session_meta 只有 session_id 无 cwd：目录保持 Missing（不臆造）。
        let input = concat!(
            r#"{"timestamp":"2026-07-19T15:40:00.000Z","type":"session_meta","payload":{"session_id":"s-1"}}"#,
            "\n",
            r#"{"timestamp":"2026-07-19T15:41:00.000Z","type":"response_item","payload":{"type":"message","id":"m-1","role":"user","content":[{"type":"input_text","text":"hi"}]}}"#,
        );
        let mut sink = CollectingSink::default();
        let report = CodexAdapter::new()
            .parse(input.as_bytes(), &mut sink)
            .unwrap();
        let obs = &report.session_observation;
        assert_eq!(
            obs.provider_session_id,
            MetadataResolution::Resolved("s-1".to_string())
        );
        assert_eq!(obs.original_working_directory, MetadataResolution::Missing);
        assert!(!obs.pair_observed);
        assert!(!obs.multi_session);
    }

    #[test]
    fn parse_observation_blank_values_are_missing() {
        // 空白 session_id → 不计（不 Resolved）；非空 sid + 空白 cwd → 目录
        // Missing。空白 sid 上的 cwd 不被接受（无非空 sid 不配 pair）。
        let input = concat!(
            r#"{"timestamp":"t1","type":"session_meta","payload":{"session_id":"   ","cwd":"/tmp/synthetic-a"}}"#,
            "\n",
            r#"{"timestamp":"t2","type":"session_meta","payload":{"session_id":"s-1","cwd":"   "}}"#,
            "\n",
            r#"{"timestamp":"t3","type":"response_item","payload":{"type":"message","id":"m-1","role":"user","content":[{"type":"input_text","text":"hi"}]}}"#,
        );
        let mut sink = CollectingSink::default();
        let report = CodexAdapter::new()
            .parse(input.as_bytes(), &mut sink)
            .unwrap();
        let obs = &report.session_observation;
        assert_eq!(
            obs.provider_session_id,
            MetadataResolution::Resolved("s-1".to_string())
        );
        assert_eq!(obs.original_working_directory, MetadataResolution::Missing);
        assert!(!obs.pair_observed);
        assert!(!obs.multi_session);
    }

    #[test]
    fn parse_observation_repeated_identical_meta_not_ambiguous() {
        // 相同 session_meta（同 sid 同 cwd）出现两次 → 单值不歧义，无多会话诊断。
        let meta = r#"{"timestamp":"t","type":"session_meta","payload":{"session_id":"s-1","cwd":"/tmp/synthetic-proj"}}"#;
        let msg = r#"{"timestamp":"t","type":"response_item","payload":{"type":"message","id":"m-1","role":"user","content":[{"type":"input_text","text":"hi"}]}}"#;
        let input = format!("{meta}\n{msg}\n{meta}");
        let mut sink = CollectingSink::default();
        let report = CodexAdapter::new()
            .parse(input.as_bytes(), &mut sink)
            .unwrap();
        let obs = &report.session_observation;
        assert_eq!(
            obs.provider_session_id,
            MetadataResolution::Resolved("s-1".to_string())
        );
        assert_eq!(
            obs.original_working_directory,
            MetadataResolution::Resolved("/tmp/synthetic-proj".to_string())
        );
        assert!(obs.pair_observed);
        assert!(!obs.multi_session);
        assert!(
            !report
                .diagnostics
                .iter()
                .any(|d| d.contains("不同 session id")),
            "重复相同 sid 不得产生多会话诊断: {:?}",
            report.diagnostics
        );
    }

    #[test]
    fn parse_observation_multi_session_fails_closed() {
        // 两条不同 sid 的 session_meta → multi_session + provider_session_id
        // Ambiguous（不把首条 id 当权威 Resume 声明）；首会话 pair 目录保持观测值。
        let first = r#"{"timestamp":"t1","type":"session_meta","payload":{"session_id":"sess-first","cwd":"/tmp/first-dir"}}"#;
        let second = r#"{"timestamp":"t2","type":"session_meta","payload":{"session_id":"sess-second","cwd":"/tmp/second-dir"}}"#;
        let msg = r#"{"timestamp":"t3","type":"response_item","payload":{"type":"message","id":"m-1","role":"user","content":[{"type":"input_text","text":"hi"}]}}"#;
        let input = format!("{first}\n{second}\n{msg}");
        let mut sink = CollectingSink::default();
        let report = CodexAdapter::new()
            .parse(input.as_bytes(), &mut sink)
            .unwrap();
        let obs = &report.session_observation;
        assert!(obs.multi_session);
        assert_eq!(obs.provider_session_id, MetadataResolution::Ambiguous);
        assert_eq!(
            obs.original_working_directory,
            MetadataResolution::Resolved("/tmp/first-dir".to_string())
        );
        assert!(obs.pair_observed);
        // 现有诊断契约不变。
        assert!(
            report
                .diagnostics
                .iter()
                .any(|d| d.contains("不同 session id"))
        );
    }

    #[test]
    fn parse_observation_never_splices_cwd_from_second_session_meta() {
        // 首会话 session_meta 无 cwd，第二会话有 cwd → 目录 Missing，绝不跨会话拼 pair。
        let first =
            r#"{"timestamp":"t1","type":"session_meta","payload":{"session_id":"sess-first"}}"#;
        let second = r#"{"timestamp":"t2","type":"session_meta","payload":{"session_id":"sess-second","cwd":"/tmp/second-dir"}}"#;
        let msg = r#"{"timestamp":"t3","type":"response_item","payload":{"type":"message","id":"m-1","role":"user","content":[{"type":"input_text","text":"hi"}]}}"#;
        let input = format!("{first}\n{second}\n{msg}");
        let mut sink = CollectingSink::default();
        let report = CodexAdapter::new()
            .parse(input.as_bytes(), &mut sink)
            .unwrap();
        let obs = &report.session_observation;
        assert!(obs.multi_session);
        assert_eq!(obs.provider_session_id, MetadataResolution::Ambiguous);
        assert_eq!(obs.original_working_directory, MetadataResolution::Missing);
        assert!(!obs.pair_observed);
    }

    #[test]
    fn parse_observation_ignores_turn_context_cwd() {
        // turn_context 的 cwd 是 turn-scoped，绝不作为 working directory（R2）；
        // turn_context 携带的 session_id 同样不被收集（不触发多会话）。
        let meta = r#"{"timestamp":"t1","type":"session_meta","payload":{"session_id":"s-1","cwd":"/tmp/meta-dir"}}"#;
        let turn = r#"{"timestamp":"t2","type":"turn_context","payload":{"type":"turn_context","session_id":"s-turn-scoped","cwd":"/tmp/turn-dir"}}"#;
        let msg = r#"{"timestamp":"t3","type":"response_item","payload":{"type":"message","id":"m-1","role":"user","content":[{"type":"input_text","text":"hi"}]}}"#;
        let input = format!("{meta}\n{turn}\n{msg}");
        let mut sink = CollectingSink::default();
        let report = CodexAdapter::new()
            .parse(input.as_bytes(), &mut sink)
            .unwrap();
        let obs = &report.session_observation;
        assert_eq!(
            obs.provider_session_id,
            MetadataResolution::Resolved("s-1".to_string())
        );
        assert_eq!(
            obs.original_working_directory,
            MetadataResolution::Resolved("/tmp/meta-dir".to_string())
        );
        assert!(obs.pair_observed);
        assert!(!obs.multi_session);
    }

    #[test]
    fn parse_observation_turn_context_cwd_alone_never_becomes_directory() {
        // 只有 turn_context 带 cwd（session_meta 无 cwd）→ 目录保持 Missing。
        let meta = r#"{"timestamp":"t1","type":"session_meta","payload":{"session_id":"s-1"}}"#;
        let turn = r#"{"timestamp":"t2","type":"turn_context","payload":{"type":"turn_context","session_id":"s-1","cwd":"/tmp/turn-dir"}}"#;
        let msg = r#"{"timestamp":"t3","type":"response_item","payload":{"type":"message","id":"m-1","role":"user","content":[{"type":"input_text","text":"hi"}]}}"#;
        let input = format!("{meta}\n{turn}\n{msg}");
        let mut sink = CollectingSink::default();
        let report = CodexAdapter::new()
            .parse(input.as_bytes(), &mut sink)
            .unwrap();
        let obs = &report.session_observation;
        assert_eq!(
            obs.provider_session_id,
            MetadataResolution::Resolved("s-1".to_string())
        );
        assert_eq!(obs.original_working_directory, MetadataResolution::Missing);
        assert!(!obs.pair_observed);
        assert!(!obs.multi_session);
    }

    #[test]
    fn parse_observation_diagnostics_never_leak_working_directories() {
        // 隐私（PRD R4）：多会话诊断只含数量 + 有界 id 列表，绝不包含 cwd 路径。
        let first = r#"{"timestamp":"t1","type":"session_meta","payload":{"session_id":"sess-first","cwd":"/tmp/first-dir"}}"#;
        let second = r#"{"timestamp":"t2","type":"session_meta","payload":{"session_id":"sess-second","cwd":"/tmp/second-dir"}}"#;
        let msg = r#"{"timestamp":"t3","type":"response_item","payload":{"type":"message","id":"m-1","role":"user","content":[{"type":"input_text","text":"hi"}]}}"#;
        let input = format!("{first}\n{second}\n{msg}");
        let mut sink = CollectingSink::default();
        let report = CodexAdapter::new()
            .parse(input.as_bytes(), &mut sink)
            .unwrap();
        for diag in &report.diagnostics {
            assert!(!diag.contains("first-dir"), "诊断不得含 cwd: {diag}");
            assert!(!diag.contains("second-dir"), "诊断不得含 cwd: {diag}");
            assert!(!diag.contains("/tmp"), "诊断不得含路径: {diag}");
        }
    }

    #[test]
    fn prefilter_skips_non_conversational_envelope_lines_without_counting_them() {
        // Known non-conversational envelopes should be skipped by the prefilter
        // before serde is invoked, so they do not enter skipped/diagnostics.
        let noise = r#"{"timestamp":"2026-07-19T23:40:00.000Z","type":"event_msg","payload":{"type":"token_count","count":1}}"#;
        assert!(!codex_line_may_need_deserialize(noise.as_bytes()));
        let mut input = String::new();
        for _ in 0..10_000 {
            input.push_str(noise);
            input.push('\n');
        }
        // Append one authoritative message so the file is non-empty.
        input.push_str(
            r#"{"timestamp":"2026-07-19T23:41:00.000Z","type":"response_item","payload":{"type":"message","id":"msg-kept","role":"user","content":[{"type":"input_text","text":"kept"}]}}"#,
        );

        let mut sink = CollectingSink::default();
        let report = CodexAdapter::new()
            .parse(input.as_bytes(), &mut sink)
            .expect("parse synthetic rollout");
        assert_eq!(report.committed, 1);
        assert_eq!(report.skipped, 0);
        assert_eq!(sink.messages.len(), 1);
        assert_eq!(sink.messages[0].text, "kept");
    }

    #[test]
    fn prefilter_preserves_unknown_type_records_for_future_fields() {
        // Unknown legal envelopes retain the original behavior: serde accepts
        // them, no message is emitted, and they are not recoverable skips.
        let input = concat!(
            r#"{"timestamp":"t","type":"unknown-future-type","payload":{"type":"event_msg"}}"#,
            "\n",
            r#"{"timestamp":"t","type":"response_item","payload":{"type":"message","id":"m1","role":"user","content":[{"type":"input_text","text":"ok"}]}}"#,
        );
        assert!(codex_line_may_need_deserialize(
            input.lines().next().expect("unknown row").as_bytes()
        ));
        let mut sink = CollectingSink::default();
        let report = CodexAdapter::new()
            .parse(input.as_bytes(), &mut sink)
            .expect("parse synthetic rollout");
        assert_eq!(report.committed, 1);
        assert_eq!(report.skipped, 0);
        assert!(report.diagnostics.is_empty());
    }

    #[test]
    fn prefilter_uses_only_top_level_type_and_preserves_broken_rows() {
        let nested = r#"{"timestamp":"t","type":"future-record","payload":{"type":"event_msg"}}"#;
        assert!(codex_line_may_need_deserialize(nested.as_bytes()));

        let broken = r#"{"timestamp":"t","type":"event_msg","payload":{"type":"token_count"}"#;
        assert!(!codex_line_may_need_deserialize(broken.as_bytes()));
        let mut sink = CollectingSink::default();
        let report = CodexAdapter::new()
            .parse(broken.as_bytes(), &mut sink)
            .expect("parse broken rollout recoverably");
        assert_eq!(report.committed, 0);
        assert_eq!(report.skipped, 1);
        assert_eq!(report.diagnostics.len(), 1);
        assert!(report.diagnostics[0].contains("invalid JSON"));
    }

    #[test]
    fn prefilter_preserves_session_meta_for_identity() {
        // session_meta must always be parsed to establish the durable session id.
        let input = concat!(
            r#"{"timestamp":"2026-07-19T15:40:00.000Z","type":"session_meta","payload":{"session_id":"sess-prefilter","cwd":"/tmp"}}"#,
            "\n",
            r#"{"timestamp":"2026-07-19T15:41:00.000Z","type":"response_item","payload":{"type":"message","id":"m1","role":"user","content":[{"type":"input_text","text":"ok"}]}}"#,
        );
        let mut sink = CollectingSink::default();
        let report = CodexAdapter::new()
            .parse(input.as_bytes(), &mut sink)
            .expect("parse synthetic rollout");
        assert_eq!(report.session_native_id.as_deref(), Some("sess-prefilter"));
        assert_eq!(report.committed, 1);
    }

    #[test]
    #[ignore = "raw timing microbenchmark; run explicitly in release mode"]
    fn prefilter_raw_timing_10k_ignored_rows() {
        const ROWS: usize = 10_000;
        const SAMPLES: usize = 5;
        let noise = r#"{"timestamp":"2026-07-19T23:40:00.000Z","type":"event_msg","payload":{"type":"token_count","count":1}}"#;

        for sample in 1..=SAMPLES {
            let full_start = std::time::Instant::now();
            let mut full_count = 0usize;
            for _ in 0..ROWS {
                if std::hint::black_box(serde_json::from_str::<RawLine>(std::hint::black_box(
                    noise,
                )))
                .is_ok()
                {
                    full_count += 1;
                }
            }
            let full_raw_line = full_start.elapsed();

            let marker_start = std::time::Instant::now();
            let mut candidate_count = 0usize;
            for _ in 0..ROWS {
                candidate_count += usize::from(codex_line_may_need_deserialize(
                    std::hint::black_box(noise.as_bytes()),
                ));
            }
            let marker_scan = marker_start.elapsed();

            let validated_start = std::time::Instant::now();
            let mut valid_count = 0usize;
            for _ in 0..ROWS {
                let line = std::hint::black_box(noise);
                let may_need = codex_line_may_need_deserialize(line.as_bytes());
                if may_need || serde_json::from_str::<IgnoredAny>(line).is_ok() {
                    valid_count += 1;
                }
            }
            let marker_plus_syntax = validated_start.elapsed();

            assert_eq!(full_count, ROWS);
            assert_eq!(candidate_count, 0);
            assert_eq!(valid_count, ROWS);
            eprintln!(
                "provider=codex sample={sample} rows={ROWS} full_raw_line_us={} marker_scan_us={} marker_plus_syntax_us={}",
                full_raw_line.as_micros(),
                marker_scan.as_micros(),
                marker_plus_syntax.as_micros()
            );
        }
    }

    // ---- 工具活动观察（设计 R1-R6）----

    /// 解析一组合成 rollout 记录，返回 (消息数, activities)。
    fn parse_rollout_records(records: &[serde_json::Value]) -> (usize, Vec<CapturedActivity>) {
        let input = records
            .iter()
            .map(serde_json::to_string)
            .collect::<Result<Vec<_>, _>>()
            .expect("serialize synthetic rollout")
            .join("\n");
        let mut sink = CollectingSink::default();
        CodexAdapter::new()
            .parse(input.as_bytes(), &mut sink)
            .expect("parse synthetic rollout");
        (sink.messages.len(), sink.activities)
    }

    fn response_item(payload: serde_json::Value) -> serde_json::Value {
        serde_json::json!({
            "timestamp": "2026-08-15T00:00:00.000Z",
            "type": "response_item",
            "payload": payload,
        })
    }

    fn assistant_message(id: &str, text: &str) -> serde_json::Value {
        response_item(serde_json::json!({
            "type": "message",
            "id": id,
            "role": "assistant",
            "content": [{"type": "output_text", "text": text}],
        }))
    }

    #[test]
    fn parse_extracts_paired_tool_activities_from_function_calls() {
        let (messages, activities) = parse_rollout_records(&[
            assistant_message("msg_a1", "checking the sandbox"),
            response_item(serde_json::json!({
                "type": "custom_tool_call",
                "id": "call_1",
                "tool_call_id": "call_1",
                "name": "shell",
                "arguments": "{\"command\":\"cat config.toml\"}",
            })),
            response_item(serde_json::json!({
                "type": "function_call_output",
                "id": "fco_1",
                "call_id": "call_1",
                "output": "policy = \"safe\"",
                "is_error": false,
            })),
            assistant_message("msg_a2", "fixing the typo"),
            response_item(serde_json::json!({
                "type": "custom_tool_call",
                "id": "call_2",
                "name": "apply_patch",
                "arguments": {"file_path": "config.toml"},
            })),
            response_item(serde_json::json!({
                "type": "function_call_output",
                "id": "fco_2",
                "call_id": "call_2",
                "output": "patch failed",
                "is_error": true,
            })),
        ]);
        assert_eq!(messages, 2, "工具记录不产生对话消息");
        assert_eq!(activities.len(), 2);

        let shell = &activities[0];
        assert_eq!(
            shell.message_native_id, "msg_a1",
            "活动锚定在发出调用的助理消息"
        );
        assert_eq!(shell.activity.kind, ToolActivityKind::Command);
        assert_eq!(shell.activity.name, "shell");
        assert_eq!(shell.activity.target.as_deref(), Some("cat config.toml"));
        assert_eq!(shell.activity.status, ToolActivityStatus::Success);
        assert_eq!(shell.activity.actor, ToolActivityActor::Main);

        let patch = &activities[1];
        assert_eq!(
            patch.activity.kind,
            ToolActivityKind::Unknown,
            "apply_patch 不在已知闭集"
        );
        assert_eq!(patch.activity.target, None, "未知名不猜 target");
        assert_eq!(patch.activity.status, ToolActivityStatus::Error);
    }

    #[test]
    fn parse_accepts_object_form_arguments() {
        let (_, activities) = parse_rollout_records(&[
            assistant_message("msg_a1", "inspecting"),
            response_item(serde_json::json!({
                "type": "custom_tool_call",
                "id": "call_obj",
                "name": "shell",
                "arguments": {"command": "git status"},
            })),
            response_item(serde_json::json!({
                "type": "function_call_output",
                "id": "fco_obj",
                "call_id": "call_obj",
                "output": "clean",
            })),
        ]);
        assert_eq!(activities.len(), 1);
        assert_eq!(activities[0].activity.target.as_deref(), Some("git status"));
        assert_eq!(activities[0].activity.status, ToolActivityStatus::Success);
    }

    #[test]
    fn parse_marks_unpaired_custom_tool_call_as_unknown() {
        // 截断 rollout：custom_tool_call 没有 function_call_output →
        // status Unknown（设计 R4.3），绝不臆造结果。
        let (_, activities) = parse_rollout_records(&[
            assistant_message("msg_a1", "running"),
            response_item(serde_json::json!({
                "type": "custom_tool_call",
                "id": "call_x",
                "name": "shell",
                "arguments": "{\"command\":\"npm test\"}",
            })),
        ]);
        assert_eq!(activities.len(), 1);
        assert_eq!(activities[0].message_native_id, "msg_a1");
        assert_eq!(activities[0].activity.status, ToolActivityStatus::Unknown);
        assert_eq!(activities[0].activity.target.as_deref(), Some("npm test"));
    }

    #[test]
    fn parse_skips_orphan_function_call_output() {
        // function_call_output 引用不存在的 call_id：不透明（R6），静默跳过。
        let (_, activities) = parse_rollout_records(&[
            assistant_message("msg_a1", "hmm"),
            response_item(serde_json::json!({
                "type": "function_call_output",
                "id": "fco_orphan",
                "call_id": "call_missing",
                "output": "???",
                "is_error": false,
            })),
        ]);
        assert!(activities.is_empty(), "孤儿输出不得臆造活动");
    }

    #[test]
    fn parse_skips_opaque_custom_tool_call() {
        // 无 name 或无 call id 的调用是不透明记录（R6）：跳过，不登记。
        let (_, activities) = parse_rollout_records(&[
            assistant_message("msg_a1", "opaque"),
            response_item(serde_json::json!({
                "type": "custom_tool_call",
                "id": "call_noname",
                "arguments": "{\"command\":\"ls\"}",
            })),
            response_item(serde_json::json!({
                "type": "custom_tool_call",
                "name": "shell",
                "arguments": "{\"command\":\"pwd\"}",
            })),
        ]);
        assert!(activities.is_empty(), "不透明调用不得产出活动");
    }
}
