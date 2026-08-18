//! Claude Code provider adapter：把 Claude Code 的 JSONL transcript 隔离解析为
//! Canonical 事件流（落实 RFC-0002 的 probe + parse 职责）。
//!
//! 格式（variant `claude-code/jsonl-v1`）：每行一个独立 JSON 对象，形如
//! `{"type":"user"|"assistant"|..., "message":{"role":..,"content":..}}`。
//! adapter 只做格式隔离，绝不接触存储 / 检索 / UI（RFC-0002 §7）。

use agent_session_grep_domain::{ToolActivityActor, ToolActivityStatus};
use agent_session_grep_ports::{
    AdapterManifest, CanonicalEventSink, Confidence, MessageEvent, MetadataResolution, ParseReport,
    ProbeResult, ProviderAdapter, ProviderError, ToolActivityEvent, build_tool_activity,
    manifest_for,
};
use serde::{Deserialize, de::IgnoredAny};

/// 本 adapter 认证的 variant 标识。
const VARIANT_ID: &str = "claude-code/jsonl-v1";

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
// JSONL markers before invoking serde. Keep this predicate conservative: an
// unknown or ambiguous line is parsed rather than being silently discarded.
#[derive(Default)]
struct TopLevelMarkers<'a> {
    kind: Option<&'a [u8]>,
    has_message: bool,
    has_session_id: bool,
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

                match key {
                    b"message" => markers.has_message = true,
                    b"sessionId" => markers.has_session_id = true,
                    b"type" => {
                        if markers.kind.is_some() {
                            markers.kind = None;
                            markers.ambiguous = true;
                        } else if line.get(value_cursor) == Some(&b'"') {
                            let Some((value_end, value_escaped)) =
                                json_string_end(line, value_cursor)
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
                    _ => {}
                }
                cursor = key_end + 1;
            }
            _ => cursor += 1,
        }
    }
    markers
}

fn claude_line_may_need_deserialize(line: &[u8]) -> bool {
    let markers = top_level_markers(line);
    if markers.ambiguous || markers.has_message || markers.has_session_id {
        return true;
    }

    const IGNORED_TYPES: [&[u8]; 10] = [
        b"summary",
        b"custom-title",
        b"mode",
        b"permission-mode",
        b"file-history-snapshot",
        b"file-history-delta",
        b"attachment",
        b"last-prompt",
        b"queue-operation",
        b"agent-name",
    ];
    !markers
        .kind
        .is_some_and(|kind| IGNORED_TYPES.contains(&kind))
}

/// Claude Code JSONL adapter。无状态——所有解析所需信息都来自输入字节。
///
/// **单文件 = 单会话**：一个源文件预期只含一个会话（`sessionId` 贯穿全文）。
/// 若同一文件出现多个不同的 `sessionId`（如手工拼接的合并文件），全部消息仍
/// 归属首个出现的会话（保持既有 first-session 契约），解析报告会追加一条
/// 多会话诊断（PRD R3.1）。
#[derive(Debug, Default, Clone, Copy)]
pub struct ClaudeCodeAdapter;

impl ClaudeCodeAdapter {
    pub fn new() -> Self {
        ClaudeCodeAdapter
    }
}

/// 一行 transcript 的最小反序列化视图。
///
/// 只声明判定与抽取所需字段；additive 未知字段被 serde 默认忽略
/// （RFC-0002 §3：additive unknown fields 默认忽略但保留诊断）。
#[derive(Debug, Deserialize)]
struct RawLine {
    /// 顶层记录类型（`user` / `assistant` / `system` / `summary` / 工具类等）。
    #[serde(default)]
    r#type: String,
    /// 该记录的 provider-native id（Claude Code 每条对话记录都带 `uuid`）。
    #[serde(default)]
    uuid: String,
    /// 父记录的 native id（threading 边）；根消息为 null/缺失/空串。
    #[serde(default, rename = "parentUuid")]
    parent_uuid: Option<String>,
    /// ISO-8601 UTC 时间串；缺失则为 None。
    #[serde(default)]
    timestamp: Option<String>,
    /// subagent / 分支标记；缺失视为 false（主线）。
    #[serde(default, rename = "isSidechain")]
    is_sidechain: bool,
    /// Claude-generated meta prompts may be copied with enriched content and
    /// a copy-local timestamp while retaining one native message identity.
    #[serde(default, rename = "isMeta")]
    is_meta: bool,
    /// Present on the enriched copied form of Claude meta prompts.
    #[serde(default, rename = "sessionKind")]
    session_kind: Option<String>,
    /// 该 transcript 的 durable 会话 id（Claude Code 每条对话记录都携带）。
    #[serde(default, rename = "sessionId")]
    session_id: Option<String>,
    /// 会话启动时的工作目录（Resume metadata 的 Original Working Directory，
    /// ADR-0009）。真实 transcript 的顶层记录携带；缺失/空白 → None，绝不臆造。
    /// 只在与同一条记录的非空 `sessionId` 同现时被接受为 pair（R3 保关联）。
    #[serde(default)]
    cwd: Option<String>,
    /// 嵌套的 message 体（对话类记录才有）。
    #[serde(default)]
    message: Option<RawMessage>,
}

#[derive(Debug, Deserialize)]
struct RawMessage {
    #[serde(default)]
    role: String,
    /// content 可能是字符串，也可能是 content-block 数组——用 untagged 兼容。
    #[serde(default)]
    content: RawContent,
}

/// Claude 的 content 字段有两种形态：纯字符串或 block 数组。
#[derive(Debug, Deserialize, Default)]
#[serde(untagged)]
enum RawContent {
    /// 早期/简单形态：直接是字符串。
    Text(String),
    /// 结构化形态：block 数组，每个 block 可能携带 `text`。
    Blocks(Vec<RawBlock>),
    /// 缺失或 `null`——视为空内容。其余不可识别形态（如数字）会使整行
    /// 反序列化失败 → 该行 recoverable skip，而非当作空内容吞掉。
    #[default]
    Empty,
}

#[derive(Debug, Deserialize)]
struct RawBlock {
    /// Block discriminator used only for narrowly-scoped provider
    /// normalization; unknown block kinds remain non-fatal.
    #[serde(default, rename = "type")]
    kind: String,
    /// 仅抽取带 `text` 的 block（如 `type:"text"`）；工具调用块无 text，忽略。
    #[serde(default)]
    text: Option<String>,
    /// `tool_result` block 的载荷在 `content`（字符串或 text block 数组），
    /// 真实工具输出（文件内容、命令输出）由此携带；缺失则为 None。
    #[serde(default)]
    content: Option<RawContent>,
    /// `tool_use` block 的调用 id（Claude Code 的 `id`，如 `toolu_01...`）。
    #[serde(default)]
    id: Option<String>,
    /// `tool_result` block 引用的调用 id（与 `tool_use` 的 `id` 配对）。
    #[serde(default, rename = "tool_use_id")]
    tool_use_id: Option<String>,
    /// `tool_use` block 的工具名（如 `Bash` / `Read`）。缺失 → 该调用视为不透明，跳过。
    #[serde(default)]
    name: Option<String>,
    /// `tool_use` block 的输入对象（provider 记录的事实字段，target 提取依据）。
    #[serde(default)]
    input: Option<serde_json::Value>,
    /// `tool_result` block 的失败标记；缺失视为 false（成功）。
    #[serde(default, rename = "is_error")]
    is_error: bool,
}

/// 一次尚未配对到结果的工具调用（设计 R5/R6：跨消息按 `tool_use_id` 配对）。
struct PendingToolCall {
    tool_use_id: String,
    name: String,
    input: serde_json::Value,
    /// 携带该调用的消息 native id（unpaired 调用的活动锚点）。
    caller_uuid: String,
    /// 调用方消息是否为 sidechain（设计 R3 的 actor 依据）。
    caller_is_sidechain: bool,
}

impl RawBlock {
    /// 抽取本 block 的可检索纯文本：`text` 优先，`tool_result` 的 `content`
    /// 其次，否则为空。
    fn plain_text(&self) -> Option<String> {
        if let Some(text) = self.text.as_deref() {
            return Some(text.to_string());
        }
        match &self.content {
            Some(RawContent::Text(s)) => Some(s.clone()),
            Some(RawContent::Blocks(blocks)) => {
                let joined = blocks
                    .iter()
                    .filter_map(|b| b.plain_text())
                    .collect::<Vec<_>>()
                    .join("\n");
                if joined.is_empty() {
                    None
                } else {
                    Some(joined)
                }
            }
            Some(RawContent::Empty) | None => None,
        }
    }
}

impl RawContent {
    /// 抽取可检索纯文本；block 数组按顺序拼接各 text 块。
    fn to_plain_text(&self, is_meta: bool, has_session_kind: bool) -> String {
        match self {
            RawContent::Text(s) => {
                // 与块形态同规（见 canonical_local_command_block）：字符串形态的
                // 本地命令封套同样剥离尾随换行，保证同一 native message 两种形态
                // 产出相同的 canonical text（跨副本 determinism）。
                if let Some(canonical) = canonical_local_command_block(s) {
                    return canonical.to_string();
                }
                s.clone()
            }
            RawContent::Blocks(blocks) => {
                if is_meta
                    && has_session_kind
                    && let Some(text) = canonical_enriched_meta_prompt(blocks)
                {
                    return text.to_string();
                }
                let text_blocks = blocks
                    .iter()
                    .filter_map(|b| b.plain_text())
                    .collect::<Vec<_>>();
                if let Some(command) = text_blocks
                    .first()
                    .and_then(|text| canonical_local_command_block(text))
                {
                    return command.to_string();
                }
                text_blocks.join("\n")
            }
            RawContent::Empty => String::new(),
        }
    }

    /// 块数组视图（字符串/空形态无块）。
    fn blocks(&self) -> &[RawBlock] {
        match self {
            RawContent::Blocks(blocks) => blocks.as_slice(),
            _ => &[],
        }
    }
}

/// 观察一块内容中的工具调用（设计 R1-R6）：
///
/// - `tool_use`：记入 `pending`（缺 id/name 视为不透明，R6 静默跳过）；
/// - `tool_result`：按 `tool_use_id` 配对已记调用，返回 `(call, is_error)` 待 emit；
///   无匹配 result 视为不透明（R6），静默跳过。
///
/// 返回本内容中新配对的 (调用, 是否失败) 列表，按块出现顺序。
fn observe_tool_blocks(
    content: &RawContent,
    pending: &mut Vec<PendingToolCall>,
    caller_uuid: &str,
    caller_is_sidechain: bool,
) -> Vec<(PendingToolCall, bool)> {
    let mut resolved = Vec::new();
    for block in content.blocks() {
        match block.kind.as_str() {
            "tool_use" => {
                if let (Some(tool_use_id), Some(name)) = (&block.id, &block.name)
                    && !tool_use_id.trim().is_empty()
                    && !name.trim().is_empty()
                {
                    pending.push(PendingToolCall {
                        tool_use_id: tool_use_id.clone(),
                        name: name.clone(),
                        input: block.input.clone().unwrap_or(serde_json::Value::Null),
                        caller_uuid: caller_uuid.to_string(),
                        caller_is_sidechain,
                    });
                }
            }
            "tool_result" => {
                if let Some(tool_use_id) = &block.tool_use_id
                    && let Some(index) = pending
                        .iter()
                        .position(|call| call.tool_use_id == *tool_use_id)
                {
                    resolved.push((pending.remove(index), block.is_error));
                }
            }
            _ => {}
        }
    }
    resolved
}

/// 把配对好的调用构建为活动并 emit（设计 R2/R3/R4）。
fn emit_paired_activity(
    sink: &mut dyn CanonicalEventSink,
    call: &PendingToolCall,
    is_error: bool,
    anchor_native_id: &str,
) -> agent_session_grep_ports::PortResult<()> {
    let activity = build_tool_activity(
        &call.name,
        if call.caller_is_sidechain {
            ToolActivityActor::Subagent
        } else {
            ToolActivityActor::Main
        },
        &call.input,
        if is_error {
            ToolActivityStatus::Error
        } else {
            ToolActivityStatus::Success
        },
    );
    sink.emit_activity(ToolActivityEvent {
        message_native_id: anchor_native_id,
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
        if call.caller_is_sidechain {
            ToolActivityActor::Subagent
        } else {
            ToolActivityActor::Main
        },
        &call.input,
        ToolActivityStatus::Unknown,
    );
    sink.emit_activity(ToolActivityEvent {
        message_native_id: &call.caller_uuid,
        activity,
    })
}

/// Claude copies some generated meta prompts as four blocks: two generated
/// text blocks, an image block, then the original stable prompt text. The
/// explicit meta/session markers and exact block shape are required so ordinary
/// multimodal messages keep every text block.
fn canonical_enriched_meta_prompt(blocks: &[RawBlock]) -> Option<&str> {
    match blocks {
        [first, second, image, original]
            if first.kind == "text"
                && second.kind == "text"
                && image.kind == "image"
                && original.kind == "text" =>
        {
            original.text.as_deref()
        }
        _ => None,
    }
}

/// Claude Code may enrich a local-command envelope with generated blocks while
/// retaining the same native message identity. Canonicalize only that shape.
fn canonical_local_command_block(text: &str) -> Option<&str> {
    if !text.starts_with("<command-name>")
        || !text.contains("<command-message>")
        || !text.contains("<command-args>")
    {
        return None;
    }

    Some(text.strip_suffix('\n').unwrap_or(text))
}

/// 判定一行是否是我们承认的对话记录。
///
/// Claude Code also uses `type:"system"` for event records that carry no
/// message body. A message-bearing system row remains compatible with the
/// existing adapter contract, while event-only system rows are metadata.
fn is_conversational(rec: &RawLine) -> bool {
    matches!(rec.r#type.as_str(), "user" | "assistant")
        || (rec.r#type == "system" && rec.message.is_some())
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
/// recognized"；区分"非 JSON"与"合法 JSON 但记录结构不符"，措辞不误导。
fn bad_lines_detail(bad_lines: &[(usize, bool)]) -> String {
    let non_json: Vec<usize> = bad_lines
        .iter()
        .filter(|(_, is_non_json)| *is_non_json)
        .map(|(no, _)| *no)
        .collect();
    let shape: Vec<usize> = bad_lines
        .iter()
        .filter(|(_, is_non_json)| !*is_non_json)
        .map(|(no, _)| *no)
        .collect();

    let mut parts = Vec::new();
    if !non_json.is_empty() {
        parts.push(format!("第 {} 行不是有效 JSON", list_line_nos(&non_json)));
    }
    if !shape.is_empty() {
        parts.push(format!(
            "第 {} 行是合法 JSON 但记录结构不受支持",
            list_line_nos(&shape)
        ));
    }
    format!(
        "{}。请修复或删除这些行后重试（该文件应为每行一条 JSON 对话记录的 Claude Code transcript）",
        parts.join("；")
    )
}

impl ProviderAdapter for ClaudeCodeAdapter {
    fn provider_id(&self) -> &str {
        "claude-code"
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
                "empty input: no non-blank lines to probe；请确认该文件不是空文件，且是 Claude Code 的 JSONL transcript"
                    .into(),
            ));
        }

        let mut json_lines = 0usize;
        let mut typed_lines = 0usize;
        let mut conversational = 0usize;
        let mut bad_lines: Vec<(usize, bool)> = Vec::new();
        for &(line_no, line) in &sample {
            match serde_json::from_str::<RawLine>(line) {
                Ok(rec) => {
                    json_lines += 1;
                    if !rec.r#type.is_empty() {
                        typed_lines += 1;
                    }
                    if is_conversational(&rec) {
                        conversational += 1;
                    }
                }
                Err(_) => {
                    // 区分"语法非 JSON"与"合法 JSON 但 shape 不符"（如 content: 42），
                    // 证据措辞不误导。
                    let is_non_json = serde_json::from_str::<serde_json::Value>(line).is_err();
                    bad_lines.push((line_no, is_non_json));
                    unmatched.push(if is_non_json {
                        format!("line {line_no}: found a non-JSON line")
                    } else {
                        format!("line {line_no}: found valid JSON with an unsupported record shape")
                    });
                }
            }
        }

        // 样本内少量未解析行（≤ 容忍度且至少有一行可解析）不是整源拒绝的理由：
        // 降一档置信度继续——解析阶段会对这些行逐行跳过并给出诊断（PRD R2.1）。
        // 超过容忍度，或一行都没解析出来（整文件是垃圾而非"带破损行的 transcript"）
        // → 整源拒绝，错误携带行号定位与修复方向（PRD R2.2）。
        if !bad_lines.is_empty() {
            if bad_lines.len() > SAMPLE_BROKEN_TOLERANCE || json_lines == 0 {
                return Err(ProviderError::AmbiguousVariant(format!(
                    "not line-delimited JSON of supported records: {}/{} sampled lines parsed。{}",
                    json_lines,
                    sample.len(),
                    bad_lines_detail(&bad_lines)
                )));
            }
            let bad_nos: Vec<usize> = bad_lines.iter().map(|(no, _)| *no).collect();
            unmatched.push(format!(
                "第 {} 行未解析——在样本容忍度内（≤{SAMPLE_BROKEN_TOLERANCE}），置信度降一档",
                list_line_nos(&bad_nos)
            ));
        }
        matched.push(format!("{json_lines} sampled lines are valid JSON objects"));

        // 判定置信度：有 type 字段且出现对话类型 → confirmed；
        // 全是 JSON 但无可识别的对话 type → low（可能是别的 JSONL）。
        let mut confidence = if typed_lines == sample.len() && conversational > 0 {
            matched.push(format!(
                "{typed_lines} lines carry a `type`, {conversational} are conversational"
            ));
            Confidence::Confirmed
        } else if conversational > 0 {
            matched.push(format!("{conversational} conversational lines present"));
            unmatched.push(format!(
                "{} lines lack a `type` field",
                sample.len() - typed_lines
            ));
            Confidence::High
        } else {
            unmatched.push("no conversational (user/assistant/system) records found".into());
            Confidence::Low
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
        // 本文件出现的全部非空 sessionId（单文件=单会话契约的检测输入）。
        let mut session_ids: Vec<String> = Vec::new();
        // seq 是会话内单调序号，只对成功 emit 的对话消息递增，
        // 从而满足 domain Session 的 seq 从 0 连续的不变量。
        let mut seq: u32 = 0;
        // 工具活动观察（设计 R1-R6）：按 `tool_use_id` 跨消息配对的待决调用。
        let mut pending_calls: Vec<PendingToolCall> = Vec::new();

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
            if !claude_line_may_need_deserialize(parse_line.as_bytes())
                && serde_json::from_str::<IgnoredAny>(parse_line).is_ok()
            {
                continue;
            }
            let rec: RawLine = match serde_json::from_str(parse_line) {
                Ok(r) => r,
                Err(e) => {
                    // 单行 JSON 破损属于 record_recoverable：跳过并标记，不整体失败。
                    report.skipped += 1;
                    // 区分"语法非 JSON"与"合法 JSON 但 shape 不符"（如 content: 42），
                    // 诊断措辞不把后者误报为非 JSON。
                    if serde_json::from_str::<serde_json::Value>(parse_line).is_ok() {
                        report.diagnostics.push(format!(
                            "line {}: valid JSON but unsupported record shape, skipped ({e})",
                            line_no + 1
                        ));
                    } else {
                        report
                            .diagnostics
                            .push(format!("line {}: invalid JSON, skipped ({e})", line_no + 1));
                    }
                    continue;
                }
            };

            // 首个携带 sessionId 的记录确定本 transcript 的 durable 会话 id；
            // 同时收集全部非空 sessionId，供末尾的多会话诊断（PRD R3.1）。
            if let Some(sid) = rec.session_id.as_deref()
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
                // sessionId；只有 sid 无 cwd 时目录保持 Missing（显式缺失不臆造）。
                if report.session_observation.provider_session_id == MetadataResolution::Missing {
                    report.session_observation.provider_session_id =
                        MetadataResolution::Resolved(sid.to_string());
                }
                // Original Working Directory 只从「同一条记录同时携带非空
                // sessionId 与 cwd」的首个 pair 观测，且该 pair 必须属于首个
                // 会话——其它会话记录上的 cwd 绝不拼接进来（R3 保关联，绝不
                // 把不同记录/会话的值拼成假 pair）。
                if !report.session_observation.pair_observed
                    && report.session_native_id.as_deref() == Some(sid)
                    && let Some(cwd) = rec.cwd.as_deref()
                    && !cwd.trim().is_empty()
                {
                    report.session_observation.original_working_directory =
                        MetadataResolution::Resolved(cwd.trim().to_string());
                    report.session_observation.pair_observed = true;
                }
            }

            // 非对话记录（工具结果、summary 等）不产生 Canonical 消息，静默略过。
            if !is_conversational(&rec) {
                continue;
            }

            let Some(msg) = rec.message else {
                report.skipped += 1;
                report.diagnostics.push(format!(
                    "line {}: conversational record without `message`, skipped",
                    line_no + 1
                ));
                continue;
            };

            let role = if msg.role.is_empty() {
                &rec.r#type
            } else {
                &msg.role
            };
            let body = msg
                .content
                .to_plain_text(rec.is_meta, rec.session_kind.is_some());
            // `isMeta` records are generated/copied by Claude Code. Real corpus
            // copies retain one UUID but report different top-level timestamps,
            // so no stable provider timestamp exists for this entity.
            let timestamp = if rec.is_meta {
                None
            } else {
                rec.timestamp.as_deref()
            };

            // 工具活动观察：先在本记录内容块里配对/登记（设计 R5/R6），
            // 消息 emit 之后按块顺序 emit 本记录配对的 activities。
            let paired = observe_tool_blocks(
                &msg.content,
                &mut pending_calls,
                &rec.uuid,
                rec.is_sidechain,
            );

            sink.emit_message(MessageEvent {
                seq,
                native_id: &rec.uuid,
                // 空串 parentUuid 语义等价于 null（根消息）；透传空串会在
                // 上层派生悬空父边，故归一化为 None。
                parent_native_id: rec.parent_uuid.as_deref().filter(|s| !s.is_empty()),
                role,
                text: &body,
                timestamp,
                is_sidechain: rec.is_sidechain,
                // 该消息来源行在快照字节中的区间（end 排他，不含换行）。
                span: Some((start, end)),
            })
            .map_err(|e| ProviderError::StructuralFatal(e.to_string()))?;
            seq += 1;
            report.committed += 1;

            for (call, is_error) in paired {
                emit_paired_activity(sink, &call, is_error, &rec.uuid)
                    .map_err(|e| ProviderError::StructuralFatal(e.to_string()))?;
            }
        }

        // 文件末尾仍未配对的调用：以 Unknown 状态如实上报（设计 R4.3）。
        for call in &pending_calls {
            emit_unpaired_activity(sink, call)
                .map_err(|e| ProviderError::StructuralFatal(e.to_string()))?;
        }

        // 多会话诊断（PRD R3.1）：单文件=单会话。同一文件出现多个不同 sessionId
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
                "文件包含 {} 个不同 sessionId（{}）——单文件=单会话，全部消息归属首个会话 {}",
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
        let adapter = ClaudeCodeAdapter::new();
        let manifest = adapter.manifest();
        assert_eq!(manifest.provider_id, adapter.provider_id());
        assert_eq!(manifest.supported_variants, vec![VARIANT_ID.to_string()]);
        assert_eq!(manifest.capabilities.provider_id, adapter.provider_id());
        assert_eq!(manifest.capabilities.variant_id, VARIANT_ID);
        assert!(manifest.last_certified_targets.is_empty());
        assert_eq!(manifest.fixture_revision, Some(1));
    }

    /// 收集 emit 的消息事件，供断言解析结果（含 native 身份/threading）。
    #[derive(Default)]
    struct CollectingSink {
        messages: Vec<Captured>,
        activities: Vec<CapturedActivity>,
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

    const SAMPLE: &str = r#"{"type":"user","uuid":"u-1","parentUuid":null,"sessionId":"sess-abc","timestamp":"2026-06-27T13:57:42.685Z","message":{"role":"user","content":"hello there"}}
{"type":"assistant","uuid":"a-2","parentUuid":"u-1","sessionId":"sess-abc","isSidechain":true,"message":{"role":"assistant","content":[{"type":"text","text":"hi"},{"type":"text","text":"friend"}]}}
{"type":"summary","summary":"ignored non-conversational"}"#;

    fn parse_single_content(content: serde_json::Value) -> String {
        let input = serde_json::to_vec(&serde_json::json!({
            "type": "user",
            "uuid": "shared-command-id",
            "sessionId": "synthetic-command-session",
            "message": {
                "role": "user",
                "content": content,
            },
        }))
        .expect("serialize synthetic transcript");
        let mut sink = CollectingSink::default();
        ClaudeCodeAdapter::new()
            .parse(&input, &mut sink)
            .expect("parse synthetic transcript");
        assert_eq!(sink.messages.len(), 1);
        sink.messages.remove(0).text
    }

    #[test]
    fn probe_confirms_claude_jsonl() {
        let r = ClaudeCodeAdapter::new().probe(SAMPLE.as_bytes()).unwrap();
        assert_eq!(r.variant_id, VARIANT_ID);
        assert_eq!(r.confidence, Confidence::Confirmed);
    }

    #[test]
    fn probe_rejects_non_jsonl() {
        let err = ClaudeCodeAdapter::new()
            .probe(b"this is not json\nnor is this")
            .unwrap_err();
        assert!(matches!(err, ProviderError::AmbiguousVariant(_)));
    }

    #[test]
    fn probe_rejects_empty() {
        let err = ClaudeCodeAdapter::new().probe(b"   \n  \n").unwrap_err();
        assert!(matches!(err, ProviderError::AmbiguousVariant(_)));
    }

    #[test]
    fn probe_accepts_utf8_bom_prefix() {
        // Windows 编辑器可能给文件加 UTF-8 BOM：probe 必须先剥离再判定。
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"\xEF\xBB\xBF");
        bytes.extend_from_slice(SAMPLE.as_bytes());
        let r = ClaudeCodeAdapter::new().probe(&bytes).unwrap();
        assert_eq!(r.confidence, Confidence::Confirmed);
    }

    #[test]
    fn probe_distinguishes_shape_mismatch_from_bad_json() {
        // `content: 42` 是合法 JSON 但 RawLine shape 不符；拒绝措辞不得归为"非 JSON"。
        let err = ClaudeCodeAdapter::new()
            .probe(b"{\"type\":\"user\",\"message\":{\"role\":\"user\",\"content\":42}}")
            .unwrap_err();
        let ProviderError::AmbiguousVariant(msg) = &err else {
            panic!("expected AmbiguousVariant, got {err:?}");
        };
        assert!(
            msg.contains("supported records"),
            "拒绝措辞应区分 shape 不符而非非 JSON: {msg}"
        );
    }

    #[test]
    fn probe_tolerates_broken_line_within_tolerance() {
        // 1 条非 JSON 行 ≤ 容忍度（3）：不整源拒绝，置信度降一档
        // （无破损时为 High → Low），并保留 tolerance 证据（PRD R2.1）。
        let input = format!(
            "{}\nthis is not json\n{}",
            SAMPLE.lines().next().unwrap(),
            SAMPLE.lines().nth(1).unwrap()
        );
        let r = ClaudeCodeAdapter::new().probe(input.as_bytes()).unwrap();
        assert_eq!(r.confidence, Confidence::Low);
        assert!(
            r.unmatched_evidence.iter().any(|e| e.contains("容忍")),
            "unmatched evidence 应说明容忍降档: {:?}",
            r.unmatched_evidence
        );
    }

    #[test]
    fn probe_tolerates_up_to_three_broken_lines() {
        // 恰好 3 条破损行 + 至少一条可解析行 → 仍在容忍度内，不拒绝。
        let input = "bad one\nbad two\nbad three\n".to_string() + SAMPLE.lines().next().unwrap();
        let r = ClaudeCodeAdapter::new().probe(input.as_bytes()).unwrap();
        assert_eq!(r.confidence, Confidence::Low); // would-be High → Low
    }

    #[test]
    fn probe_tolerates_shape_mismatch_line_within_tolerance() {
        // shape 不符行同样计入容忍度：1 条合法 JSON 但结构不支持的行不整源拒绝。
        let input = format!(
            "{}\n{}\n{{\"type\":\"user\",\"message\":{{\"role\":\"user\",\"content\":42}}}}",
            SAMPLE.lines().next().unwrap(),
            SAMPLE.lines().nth(1).unwrap()
        );
        let r = ClaudeCodeAdapter::new().probe(input.as_bytes()).unwrap();
        assert_eq!(r.confidence, Confidence::Low);
    }

    #[test]
    fn probe_rejects_broken_lines_beyond_tolerance_with_line_numbers() {
        // 破损行数超过容忍度（4 > 3）：整源拒绝，错误携带"第 N 行"定位
        // 与修复方向（PRD R2.2），绝不裸报。
        let input = format!(
            "{}\n{}\n{}\n{}\n{}",
            "this is not json 1",
            "this is not json 2",
            "this is not json 3",
            "this is not json 4",
            SAMPLE.lines().next().unwrap(),
        );
        let err = ClaudeCodeAdapter::new()
            .probe(input.as_bytes())
            .unwrap_err();
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
        // 同一文件出现两个不同 sessionId（手工拼接的合并文件）：不静默折叠——
        // 产出诊断（数量 + id），归属仍为首个会话（PRD R3.1）。
        let first = SAMPLE
            .lines()
            .next()
            .unwrap()
            .replace("sess-abc", "sess-first");
        let second = SAMPLE
            .lines()
            .nth(1)
            .unwrap()
            .replace("sess-abc", "sess-second");
        let input = format!("{first}\n{second}");
        let mut sink = CollectingSink::default();
        let report = ClaudeCodeAdapter::new()
            .parse(input.as_bytes(), &mut sink)
            .unwrap();
        assert_eq!(report.session_native_id.as_deref(), Some("sess-first"));
        assert_eq!(report.committed, 2);
        let diag = report
            .diagnostics
            .iter()
            .find(|d| d.contains("不同 sessionId"))
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
        let report = ClaudeCodeAdapter::new()
            .parse(SAMPLE.as_bytes(), &mut sink)
            .unwrap();
        assert!(report.session_native_id.is_some());
        assert!(
            !report
                .diagnostics
                .iter()
                .any(|d| d.contains("不同 sessionId")),
            "单会话文件不得产生多会话诊断: {:?}",
            report.diagnostics
        );
    }

    #[test]
    fn parse_extracts_conversational_messages() {
        let mut sink = CollectingSink::default();
        let report = ClaudeCodeAdapter::new()
            .parse(SAMPLE.as_bytes(), &mut sink)
            .unwrap();
        // 两条对话消息被提交，summary 行被略过（不计入 skipped，因为它不是错误）。
        assert_eq!(report.committed, 2);
        assert_eq!(sink.messages.len(), 2);
        // seq 从 0 连续。
        assert_eq!(sink.messages[0].seq, 0);
        assert_eq!(sink.messages[1].seq, 1);
        // 字符串 content 与 block 数组 content 都被正确抽取。
        assert_eq!(sink.messages[0].text, "hello there");
        assert_eq!(sink.messages[1].text, "hi\nfriend");
        // 角色标签透传。
        assert_eq!(sink.messages[0].role, "user");
        assert_eq!(sink.messages[1].role, "assistant");
        // native 身份与 threading：uuid 原样透传，parentUuid 形成链，根消息 parent 为 None。
        assert_eq!(sink.messages[0].native_id, "u-1");
        assert_eq!(sink.messages[0].parent_native_id, None);
        assert_eq!(sink.messages[1].native_id, "a-2");
        assert_eq!(sink.messages[1].parent_native_id.as_deref(), Some("u-1"));
        // timestamp 原样透传；缺失为 None。
        assert_eq!(
            sink.messages[0].timestamp.as_deref(),
            Some("2026-06-27T13:57:42.685Z")
        );
        assert_eq!(sink.messages[1].timestamp, None);
        // isSidechain：缺失视为主线 false，显式 true 被捕获。
        assert!(!sink.messages[0].is_sidechain);
        assert!(sink.messages[1].is_sidechain);
    }

    #[test]
    fn parse_canonicalizes_string_and_enriched_local_command_forms() {
        let envelope = "<command-name>synthetic-local</command-name>\n\
                        <command-message>run synthetic local command</command-message>\n\
                        <command-args>--flag value</command-args>";
        let string_form = parse_single_content(serde_json::json!(envelope));
        let enriched_form = parse_single_content(serde_json::json!([
            {"type": "text", "text": format!("{envelope}\n")},
            {"type": "text", "text": "synthetic stdout"},
            {"type": "text", "text": "synthetic generated output"}
        ]));

        assert_eq!(string_form, envelope);
        assert_eq!(enriched_form, string_form);
    }

    #[test]
    fn parse_canonicalizes_string_form_local_command_with_trailing_newline() {
        let envelope = "<command-name>synthetic-local</command-name>\n\
                        <command-message>run synthetic local command</command-message>\n\
                        <command-args>--flag value</command-args>";
        // 字符串形态带尾随换行时，必须与块形态同规：剥掉尾随 `\n`。
        let string_form = parse_single_content(serde_json::json!(format!("{envelope}\n")));
        assert_eq!(string_form, envelope);
    }

    #[test]
    fn parse_preserves_ordinary_multiblock_text_and_whitespace() {
        let text = parse_single_content(serde_json::json!([
            {"type": "text", "text": " ordinary first block "},
            {"type": "tool_use", "name": "Synthetic", "input": {}},
            {"type": "text", "text": "ordinary second block\n"}
        ]));

        assert_eq!(text, " ordinary first block \nordinary second block\n");
    }

    #[test]
    fn parse_keeps_genuinely_different_local_command_text_distinct() {
        let first = "<command-name>synthetic-local</command-name>\n\
                     <command-message>run synthetic local command</command-message>\n\
                     <command-args>--flag first</command-args>";
        let second = "<command-name>synthetic-local</command-name>\n\
                      <command-message>run synthetic local command</command-message>\n\
                      <command-args>--flag second</command-args>";
        let string_form = parse_single_content(serde_json::json!(first));
        let enriched_form = parse_single_content(serde_json::json!([
            {"type": "text", "text": format!("{second}\n")},
            {"type": "text", "text": "synthetic stdout"}
        ]));

        assert_eq!(string_form, first);
        assert_eq!(enriched_form, second);
        assert_ne!(string_form, enriched_form);
    }

    #[test]
    fn parse_ignores_event_only_system_records() {
        let input = br#"{"type":"system","subtype":"synthetic-event","uuid":"event-1"}
{"type":"user","uuid":"user-1","message":{"role":"user","content":"kept"}}"#;
        let mut sink = CollectingSink::default();
        let report = ClaudeCodeAdapter::new()
            .parse(input, &mut sink)
            .expect("parse synthetic transcript");

        assert_eq!(report.committed, 1);
        assert_eq!(report.skipped, 0);
        assert_eq!(sink.messages.len(), 1);
        assert_eq!(sink.messages[0].text, "kept");
    }

    #[test]
    fn parse_keeps_message_bearing_system_records() {
        let input = br#"{"type":"system","uuid":"system-1","message":{"role":"system","content":"kept system message"}}"#;
        let mut sink = CollectingSink::default();
        let report = ClaudeCodeAdapter::new()
            .parse(input, &mut sink)
            .expect("parse synthetic transcript");

        assert_eq!(report.committed, 1);
        assert_eq!(report.skipped, 0);
        assert_eq!(sink.messages.len(), 1);
        assert_eq!(sink.messages[0].role, "system");
        assert_eq!(sink.messages[0].text, "kept system message");
    }

    #[test]
    fn parse_still_skips_user_records_without_messages() {
        let input = br#"{"type":"user","uuid":"user-without-message"}"#;
        let mut sink = CollectingSink::default();
        let report = ClaudeCodeAdapter::new()
            .parse(input, &mut sink)
            .expect("parse synthetic transcript");

        assert_eq!(report.committed, 0);
        assert_eq!(report.skipped, 1);
        assert!(sink.messages.is_empty());
    }

    #[test]
    fn parse_canonicalizes_original_and_enriched_meta_prompt_forms() {
        let original = serde_json::json!({
            "type": "user",
            "uuid": "shared-meta-id",
            "isMeta": true,
            "timestamp": "2026-01-01T00:04:00Z",
            "message": {
                "role": "user",
                "content": [{"type": "text", "text": "stable synthetic meta prompt"}],
            },
        });
        let enriched = serde_json::json!({
            "type": "user",
            "uuid": "shared-meta-id",
            "isMeta": true,
            "sessionKind": "synthetic-copy",
            "timestamp": "2026-01-01T00:00:00Z",
            "message": {
                "role": "user",
                "content": [
                    {"type": "text", "text": "synthetic generated prefix"},
                    {"type": "text", "text": "synthetic generated instructions"},
                    {"type": "image", "source": {"type": "base64", "data": "AA=="}},
                    {"type": "text", "text": "stable synthetic meta prompt"},
                ],
            },
        });

        let parse = |record: serde_json::Value| {
            let input = serde_json::to_vec(&record).expect("serialize synthetic transcript");
            let mut sink = CollectingSink::default();
            ClaudeCodeAdapter::new()
                .parse(&input, &mut sink)
                .expect("parse synthetic transcript");
            assert_eq!(sink.messages.len(), 1);
            sink.messages.remove(0)
        };
        let original = parse(original);
        let enriched = parse(enriched);

        assert_eq!(original.text, "stable synthetic meta prompt");
        assert_eq!(enriched.text, original.text);
        assert_eq!(original.timestamp, None);
        assert_eq!(enriched.timestamp, None);
    }

    #[test]
    fn parse_preserves_similar_multimodal_content_without_meta_markers() {
        let input = serde_json::to_vec(&serde_json::json!({
            "type": "user",
            "uuid": "ordinary-multimodal-id",
            "message": {
                "role": "user",
                "content": [
                    {"type": "text", "text": "ordinary first"},
                    {"type": "text", "text": "ordinary second"},
                    {"type": "image", "source": {"type": "base64", "data": "AA=="}},
                    {"type": "text", "text": "ordinary last"},
                ],
            },
        }))
        .expect("serialize synthetic transcript");
        let mut sink = CollectingSink::default();
        ClaudeCodeAdapter::new()
            .parse(&input, &mut sink)
            .expect("parse synthetic transcript");

        assert_eq!(sink.messages.len(), 1);
        assert_eq!(
            sink.messages[0].text,
            "ordinary first\nordinary second\nordinary last"
        );
    }

    #[test]
    fn parse_preserves_meta_content_when_enrichment_shape_is_not_exact() {
        let input = serde_json::to_vec(&serde_json::json!({
            "type": "user",
            "uuid": "different-meta-id",
            "isMeta": true,
            "sessionKind": "synthetic-copy",
            "message": {
                "role": "user",
                "content": [
                    {"type": "text", "text": "meaningful first"},
                    {"type": "image", "source": {"type": "base64", "data": "AA=="}},
                    {"type": "text", "text": "meaningful last"},
                ],
            },
        }))
        .expect("serialize synthetic transcript");
        let mut sink = CollectingSink::default();
        ClaudeCodeAdapter::new()
            .parse(&input, &mut sink)
            .expect("parse synthetic transcript");

        assert_eq!(sink.messages.len(), 1);
        assert_eq!(sink.messages[0].text, "meaningful first\nmeaningful last");
    }

    #[test]
    fn parse_skips_broken_line_recoverably() {
        let input = "{\"type\":\"user\",\"message\":{\"role\":\"user\",\"content\":\"ok\"}}\n{not valid json}";
        let mut sink = CollectingSink::default();
        let report = ClaudeCodeAdapter::new()
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
        let report = ClaudeCodeAdapter::new().parse(&bytes, &mut sink).unwrap();
        // BOM 不改变解析结果：首行正常解析，不产生假 skip。
        assert_eq!(report.committed, 2);
        assert_eq!(report.skipped, 0);
        assert_eq!(sink.messages.len(), 2);
        // span 仍以快照字节为坐标系：BOM 是快照的一部分，首条消息的 span
        // 从偏移 0 起，切片覆盖 BOM + 来源行全文。
        let (start, end) = sink.messages[0].span.expect("span required");
        assert_eq!(start, 0);
        let mut expected = Vec::new();
        expected.extend_from_slice(b"\xEF\xBB\xBF");
        expected.extend_from_slice(SAMPLE.lines().next().unwrap().as_bytes());
        assert_eq!(&bytes[start as usize..end as usize], expected.as_slice());
    }

    #[test]
    fn parse_diagnostic_distinguishes_shape_mismatch_from_bad_json() {
        // `content: 42` 是合法 JSON 但 shape 不符：诊断必须区分，不得归为"非 JSON"。
        let input = "{\"type\":\"user\",\"message\":{\"role\":\"user\",\"content\":42}}\n{\"type\":\"user\",\"message\":{\"role\":\"user\",\"content\":\"ok\"}}";
        let mut sink = CollectingSink::default();
        let report = ClaudeCodeAdapter::new()
            .parse(input.as_bytes(), &mut sink)
            .unwrap();
        assert_eq!(report.committed, 1);
        assert_eq!(report.skipped, 1);
        let diag = &report.diagnostics[0];
        assert!(
            diag.contains("valid JSON") && diag.contains("shape"),
            "诊断应指出 shape 不符而非非 JSON: {diag}"
        );
        assert!(!diag.contains("invalid JSON"), "不得误报为非 JSON: {diag}");
    }

    #[test]
    fn parse_reports_span_roundtripping_to_source_line() {
        let bytes = SAMPLE.as_bytes();
        let mut sink = CollectingSink::default();
        ClaudeCodeAdapter::new().parse(bytes, &mut sink).unwrap();
        // 每条消息的 span 切回快照字节，必须精确等于其来源行。
        let lines: Vec<&str> = SAMPLE.lines().collect();
        for (captured, expected_line) in sink.messages.iter().zip([lines[0], lines[1]]) {
            let (start, end) = captured.span.expect("provider must report a span");
            assert_eq!(
                &bytes[start as usize..end as usize],
                expected_line.as_bytes()
            );
        }
    }

    #[test]
    fn parse_reports_span_roundtripping_on_crlf_lines() {
        // Windows 真实 transcript 常见 CRLF；span 必须不含 `\r`/`\n`，
        // 切回快照字节应等于去掉行尾换行后的记录正文。
        let line = r#"{"type":"user","uuid":"crlf-1","sessionId":"sess-crlf","message":{"role":"user","content":"crlf span"}}"#;
        let bytes = format!("{line}\r\n").into_bytes();
        let mut sink = CollectingSink::default();
        ClaudeCodeAdapter::new().parse(&bytes, &mut sink).unwrap();
        assert_eq!(sink.messages.len(), 1);
        let (start, end) = sink.messages[0].span.expect("span required");
        assert_eq!(&bytes[start as usize..end as usize], line.as_bytes());
        // end 排他：下一字节是 `\r`（CRLF 的 CR），不在 span 内。
        assert_eq!(bytes[end as usize], b'\r');
    }

    #[test]
    fn parse_source_streams_records_with_identical_spans() {
        // 生产路径：parse_source 从只读 source 逐行流式解析，span 坐标必须与
        // 整段字节 parse 完全一致（RFC-0002 §7 语义不变）。
        let bytes = SAMPLE.as_bytes();
        let source = agent_session_grep_ports::SliceSource::new(bytes);
        let mut sink = CollectingSink::default();
        ClaudeCodeAdapter::new()
            .parse_source(&source, &mut sink)
            .unwrap();
        let lines: Vec<&str> = SAMPLE.lines().collect();
        for (captured, expected_line) in sink.messages.iter().zip([lines[0], lines[1]]) {
            let (start, end) = captured.span.expect("provider must report a span");
            assert_eq!(
                &bytes[start as usize..end as usize],
                expected_line.as_bytes(),
                "流式 span 与整段 parse 必须逐字节一致"
            );
        }
    }

    #[test]
    fn parse_source_rejects_oversized_record() {
        // 大文件上限回归：单条记录超过 manifest max_record_size（8 MiB）时，
        // 流式路径必须诚实拒绝（RecordTooLarge），而不是按文件大小分配内存。
        let oversized = format!(
            "{{\"type\":\"user\",\"message\":{{\"role\":\"user\",\"content\":\"{}\"}}}}\n",
            "a".repeat((agent_session_grep_ports::STREAM_RECORD_MAX_BYTES as usize) + 1024)
        );
        let source = agent_session_grep_ports::SliceSource::new(oversized.as_bytes());
        let mut sink = CollectingSink::default();
        let err = ClaudeCodeAdapter::new()
            .parse_source(&source, &mut sink)
            .unwrap_err();
        assert!(
            matches!(err, ProviderError::RecordTooLarge { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn parse_surfaces_session_native_id() {
        let mut sink = CollectingSink::default();
        let report = ClaudeCodeAdapter::new()
            .parse(SAMPLE.as_bytes(), &mut sink)
            .unwrap();
        assert_eq!(report.session_native_id.as_deref(), Some("sess-abc"));
    }

    #[test]
    fn parse_without_session_id_reports_none() {
        let input = "{\"type\":\"user\",\"message\":{\"role\":\"user\",\"content\":\"ok\"}}";
        let mut sink = CollectingSink::default();
        let report = ClaudeCodeAdapter::new()
            .parse(input.as_bytes(), &mut sink)
            .unwrap();
        // provider 未提供 sessionId → None，显式缺失不臆造。
        assert_eq!(report.session_native_id, None);
    }

    #[test]
    fn parse_observation_reports_pair_from_same_record() {
        // 同一条记录同时携带非空 sessionId 与 cwd → pair 关联被捕获（R3 保关联）。
        let input = concat!(
            r#"{"type":"user","uuid":"u-1","sessionId":"sess-a","cwd":"/tmp/synthetic-proj","message":{"role":"user","content":"hi"}}"#,
            "\n",
            r#"{"type":"assistant","uuid":"a-1","sessionId":"sess-a","message":{"role":"assistant","content":"yo"}}"#,
        );
        let mut sink = CollectingSink::default();
        let report = ClaudeCodeAdapter::new()
            .parse(input.as_bytes(), &mut sink)
            .unwrap();
        let obs = &report.session_observation;
        assert_eq!(
            obs.provider_session_id,
            MetadataResolution::Resolved("sess-a".to_string())
        );
        assert_eq!(
            obs.original_working_directory,
            MetadataResolution::Resolved("/tmp/synthetic-proj".to_string())
        );
        assert!(obs.pair_observed);
        assert!(!obs.multi_session);
    }

    #[test]
    fn parse_observation_sid_only_keeps_directory_missing() {
        // 只有 sid 无 cwd：provider_session_id 可解析，目录保持 Missing（不臆造）。
        let input = r#"{"type":"user","uuid":"u-1","sessionId":"sess-a","message":{"role":"user","content":"hi"}}"#;
        let mut sink = CollectingSink::default();
        let report = ClaudeCodeAdapter::new()
            .parse(input.as_bytes(), &mut sink)
            .unwrap();
        let obs = &report.session_observation;
        assert_eq!(
            obs.provider_session_id,
            MetadataResolution::Resolved("sess-a".to_string())
        );
        assert_eq!(obs.original_working_directory, MetadataResolution::Missing);
        assert!(!obs.pair_observed);
        assert!(!obs.multi_session);
    }

    #[test]
    fn parse_observation_all_missing_when_fields_absent() {
        // sessionId 与 cwd 都缺失 → 全 Missing（ADR-0009 默认态）。
        let input = r#"{"type":"user","uuid":"u-1","message":{"role":"user","content":"hi"}}"#;
        let mut sink = CollectingSink::default();
        let report = ClaudeCodeAdapter::new()
            .parse(input.as_bytes(), &mut sink)
            .unwrap();
        let obs = &report.session_observation;
        assert_eq!(obs.provider_session_id, MetadataResolution::Missing);
        assert_eq!(obs.original_working_directory, MetadataResolution::Missing);
        assert!(!obs.pair_observed);
        assert!(!obs.multi_session);
    }

    #[test]
    fn parse_observation_blank_values_are_missing() {
        // 空白 sessionId / 空白 cwd 均视为缺失；空白 sid 上的 cwd 不被接受
        // （无非空 sid 不配 pair）。
        let input = concat!(
            r#"{"type":"user","uuid":"u-1","sessionId":"   ","cwd":"/tmp/synthetic-a","message":{"role":"user","content":"hi"}}"#,
            "\n",
            r#"{"type":"user","uuid":"u-2","sessionId":"sess-b","cwd":"   ","message":{"role":"user","content":"hi2"}}"#,
        );
        let mut sink = CollectingSink::default();
        let report = ClaudeCodeAdapter::new()
            .parse(input.as_bytes(), &mut sink)
            .unwrap();
        let obs = &report.session_observation;
        // 首条非空 sessionId 是 sess-b（首行 sid 空白 → 不计）。
        assert_eq!(
            obs.provider_session_id,
            MetadataResolution::Resolved("sess-b".to_string())
        );
        // 两个 cwd 都不合格：一个挂在空白 sid 上，另一个本身空白。
        assert_eq!(obs.original_working_directory, MetadataResolution::Missing);
        assert!(!obs.pair_observed);
        assert!(!obs.multi_session);
    }

    #[test]
    fn parse_observation_repeated_identical_pair_is_not_ambiguous() {
        // 同一 sid + 同一 cwd 反复出现 → 单值不歧义，无多会话诊断。
        let line = r#"{"type":"user","uuid":"u-1","sessionId":"sess-a","cwd":"/tmp/synthetic-proj","message":{"role":"user","content":"hi"}}"#;
        let input = format!("{line}\n{line}");
        let mut sink = CollectingSink::default();
        let report = ClaudeCodeAdapter::new()
            .parse(input.as_bytes(), &mut sink)
            .unwrap();
        let obs = &report.session_observation;
        assert_eq!(
            obs.provider_session_id,
            MetadataResolution::Resolved("sess-a".to_string())
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
                .any(|d| d.contains("不同 sessionId")),
            "重复相同 sid 不得产生多会话诊断: {:?}",
            report.diagnostics
        );
    }

    #[test]
    fn parse_observation_pair_from_later_record_of_first_session() {
        // pair 不必出现在首条记录：首条只有 sid，同会话后续记录带 cwd → 仍成 pair。
        let input = concat!(
            r#"{"type":"user","uuid":"u-1","sessionId":"sess-a","message":{"role":"user","content":"hi"}}"#,
            "\n",
            r#"{"type":"assistant","uuid":"a-1","sessionId":"sess-a","cwd":"/tmp/synthetic-proj","message":{"role":"assistant","content":"yo"}}"#,
        );
        let mut sink = CollectingSink::default();
        let report = ClaudeCodeAdapter::new()
            .parse(input.as_bytes(), &mut sink)
            .unwrap();
        let obs = &report.session_observation;
        assert_eq!(
            obs.provider_session_id,
            MetadataResolution::Resolved("sess-a".to_string())
        );
        assert_eq!(
            obs.original_working_directory,
            MetadataResolution::Resolved("/tmp/synthetic-proj".to_string())
        );
        assert!(obs.pair_observed);
        assert!(!obs.multi_session);
    }

    #[test]
    fn parse_observation_multi_session_fails_closed() {
        // 两个不同 sessionId → multi_session + provider_session_id Ambiguous
        // （不把首条 id 当权威 Resume 声明）；首会话的 pair 目录保持观测值。
        let first = r#"{"type":"user","uuid":"u-1","sessionId":"sess-first","cwd":"/tmp/first-dir","message":{"role":"user","content":"hi"}}"#;
        let second = r#"{"type":"user","uuid":"u-2","sessionId":"sess-second","cwd":"/tmp/second-dir","message":{"role":"user","content":"yo"}}"#;
        let input = format!("{first}\n{second}");
        let mut sink = CollectingSink::default();
        let report = ClaudeCodeAdapter::new()
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
                .any(|d| d.contains("不同 sessionId"))
        );
    }

    #[test]
    fn parse_observation_never_splices_cwd_from_other_session() {
        // 首会话无 cwd，第二会话有 cwd → 目录保持 Missing，绝不跨会话拼 pair。
        let first = r#"{"type":"user","uuid":"u-1","sessionId":"sess-first","message":{"role":"user","content":"hi"}}"#;
        let second = r#"{"type":"user","uuid":"u-2","sessionId":"sess-second","cwd":"/tmp/second-dir","message":{"role":"user","content":"yo"}}"#;
        let input = format!("{first}\n{second}");
        let mut sink = CollectingSink::default();
        let report = ClaudeCodeAdapter::new()
            .parse(input.as_bytes(), &mut sink)
            .unwrap();
        let obs = &report.session_observation;
        assert!(obs.multi_session);
        assert_eq!(obs.provider_session_id, MetadataResolution::Ambiguous);
        assert_eq!(obs.original_working_directory, MetadataResolution::Missing);
        assert!(!obs.pair_observed);
    }

    #[test]
    fn parse_observation_diagnostics_never_leak_working_directories() {
        // 隐私（PRD R4）：诊断只含行号/数量/有界 id 列表，绝不包含 cwd 路径。
        let first = r#"{"type":"user","uuid":"u-1","sessionId":"sess-first","cwd":"/tmp/first-dir","message":{"role":"user","content":"hi"}}"#;
        let second = r#"{"type":"user","uuid":"u-2","sessionId":"sess-second","cwd":"/tmp/second-dir","message":{"role":"user","content":"yo"}}"#;
        let input = format!("{first}\n{second}");
        let mut sink = CollectingSink::default();
        let report = ClaudeCodeAdapter::new()
            .parse(input.as_bytes(), &mut sink)
            .unwrap();
        for diag in &report.diagnostics {
            assert!(!diag.contains("first-dir"), "诊断不得含 cwd: {diag}");
            assert!(!diag.contains("second-dir"), "诊断不得含 cwd: {diag}");
            assert!(!diag.contains("/tmp"), "诊断不得含路径: {diag}");
        }
    }

    #[test]
    fn prefilter_skips_non_conversational_lines_without_counting_them() {
        // Known non-conversational records should be skipped by the prefilter
        // before serde is invoked, so they do not enter skipped/diagnostics.
        let noise = r#"{"type":"summary","summary":"noise"}"#;
        assert!(!claude_line_may_need_deserialize(noise.as_bytes()));
        let mut input = String::new();
        for _ in 0..10_000 {
            input.push_str(noise);
            input.push('\n');
        }
        // Append one conversational record so the file is non-empty.
        input.push_str(
            r#"{"type":"user","uuid":"u-1","sessionId":"sess-prefilter","message":{"role":"user","content":"kept"}}"#,
        );

        let mut sink = CollectingSink::default();
        let report = ClaudeCodeAdapter::new()
            .parse(input.as_bytes(), &mut sink)
            .expect("parse synthetic transcript");
        assert_eq!(report.committed, 1);
        assert_eq!(report.skipped, 0);
        assert_eq!(sink.messages.len(), 1);
        assert_eq!(sink.messages[0].text, "kept");
    }

    #[test]
    fn prefilter_preserves_unknown_type_records_for_future_fields() {
        // Unknown legal records retain the original behavior: serde accepts
        // them, no message is emitted, and they are not recoverable skips.
        let input = concat!(
            r#"{"type":"unknown-future-type","uuid":"x","future":{"type":"summary"}}"#,
            "\n",
            r#"{"type":"user","uuid":"u-1","sessionId":"s","message":{"role":"user","content":"ok"}}"#,
        );
        assert!(claude_line_may_need_deserialize(
            input.lines().next().expect("unknown row").as_bytes()
        ));
        let mut sink = CollectingSink::default();
        let report = ClaudeCodeAdapter::new()
            .parse(input.as_bytes(), &mut sink)
            .expect("parse synthetic transcript");
        assert_eq!(report.committed, 1);
        assert_eq!(report.skipped, 0);
        assert!(report.diagnostics.is_empty());
    }

    #[test]
    fn prefilter_uses_only_top_level_type_and_preserves_broken_rows() {
        let nested = r#"{"type":"future-record","payload":{"type":"summary"}}"#;
        assert!(claude_line_may_need_deserialize(nested.as_bytes()));

        let broken = r#"{"type":"summary","summary":"truncated""#;
        assert!(!claude_line_may_need_deserialize(broken.as_bytes()));
        let mut sink = CollectingSink::default();
        let report = ClaudeCodeAdapter::new()
            .parse(broken.as_bytes(), &mut sink)
            .expect("parse broken transcript recoverably");
        assert_eq!(report.committed, 0);
        assert_eq!(report.skipped, 1);
        assert_eq!(report.diagnostics.len(), 1);
        assert!(report.diagnostics[0].contains("invalid JSON"));
    }

    #[test]
    fn prefilter_preserves_session_metadata_in_non_conversational_types() {
        // file-history-snapshot lacks sessionId but is a known ignored type;
        // last-prompt carries sessionId and must still be parsed for identity.
        let input = concat!(
            r#"{"type":"file-history-snapshot","snapshot":"noise"}"#,
            "\n",
            r#"{"type":"last-prompt","sessionId":"sess-meta","prompt":"p"}"#,
            "\n",
            r#"{"type":"user","uuid":"u-1","sessionId":"sess-meta","message":{"role":"user","content":"ok"}}"#,
        );
        let mut sink = CollectingSink::default();
        let report = ClaudeCodeAdapter::new()
            .parse(input.as_bytes(), &mut sink)
            .expect("parse synthetic transcript");
        assert_eq!(report.session_native_id.as_deref(), Some("sess-meta"));
        assert_eq!(report.committed, 1);
        assert_eq!(report.skipped, 0);
    }

    #[test]
    #[ignore = "raw timing microbenchmark; run explicitly in release mode"]
    fn prefilter_raw_timing_10k_ignored_rows() {
        const ROWS: usize = 10_000;
        const SAMPLES: usize = 5;
        let noise = r#"{"type":"summary","summary":"noise"}"#;

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
                candidate_count += usize::from(claude_line_may_need_deserialize(
                    std::hint::black_box(noise.as_bytes()),
                ));
            }
            let marker_scan = marker_start.elapsed();

            let validated_start = std::time::Instant::now();
            let mut valid_count = 0usize;
            for _ in 0..ROWS {
                let line = std::hint::black_box(noise);
                let may_need = claude_line_may_need_deserialize(line.as_bytes());
                if may_need || serde_json::from_str::<IgnoredAny>(line).is_ok() {
                    valid_count += 1;
                }
            }
            let marker_plus_syntax = validated_start.elapsed();

            assert_eq!(full_count, ROWS);
            assert_eq!(candidate_count, 0);
            assert_eq!(valid_count, ROWS);
            eprintln!(
                "provider=claude-code sample={sample} rows={ROWS} full_raw_line_us={} marker_scan_us={} marker_plus_syntax_us={}",
                full_raw_line.as_micros(),
                marker_scan.as_micros(),
                marker_plus_syntax.as_micros()
            );
        }
    }

    // ---- 工具活动观察（设计 R1-R6）----

    /// 解析一组合成记录，返回 (消息数, activities)。
    fn parse_records(records: &[serde_json::Value]) -> (usize, Vec<CapturedActivity>) {
        let input = records
            .iter()
            .map(serde_json::to_string)
            .collect::<Result<Vec<_>, _>>()
            .expect("serialize synthetic records")
            .join("\n");
        let mut sink = CollectingSink::default();
        ClaudeCodeAdapter::new()
            .parse(input.as_bytes(), &mut sink)
            .expect("parse synthetic transcript");
        (sink.messages.len(), sink.activities)
    }

    fn assistant(uuid: &str, is_sidechain: bool, blocks: serde_json::Value) -> serde_json::Value {
        serde_json::json!({
            "type": "assistant",
            "uuid": uuid,
            "parentUuid": null,
            "sessionId": "sess-act",
            "isSidechain": is_sidechain,
            "message": { "role": "assistant", "content": blocks },
        })
    }

    fn user(uuid: &str, parent: &str, blocks: serde_json::Value) -> serde_json::Value {
        serde_json::json!({
            "type": "user",
            "uuid": uuid,
            "parentUuid": parent,
            "sessionId": "sess-act",
            "message": { "role": "user", "content": blocks },
        })
    }

    #[test]
    fn parse_extracts_paired_tool_activities_with_kinds_and_targets() {
        let (messages, activities) = parse_records(&[
            assistant(
                "a-1",
                false,
                serde_json::json!([
                    {"type": "text", "text": "running"},
                    {"type": "tool_use", "id": "toolu_1", "name": "Bash", "input": {"command": "ls -la"}},
                ]),
            ),
            user(
                "r-1",
                "a-1",
                serde_json::json!([
                    {"type": "tool_result", "tool_use_id": "toolu_1", "content": "total 0", "is_error": false},
                ]),
            ),
            assistant(
                "a-2",
                false,
                serde_json::json!([
                    {"type": "tool_use", "id": "toolu_2", "name": "Read", "input": {"file_path": "src/main.rs"}},
                ]),
            ),
            user(
                "r-2",
                "a-2",
                serde_json::json!([
                    {"type": "tool_result", "tool_use_id": "toolu_2", "content": "not found", "is_error": true},
                ]),
            ),
            assistant(
                "a-3",
                false,
                serde_json::json!([
                    {"type": "tool_use", "id": "toolu_3", "name": "WebFetch", "input": {"url": "https://example.test/docs"}},
                ]),
            ),
            user(
                "r-3",
                "a-3",
                serde_json::json!([
                    {"type": "tool_result", "tool_use_id": "toolu_3", "content": "fetched"},
                ]),
            ),
            assistant(
                "a-4",
                false,
                serde_json::json!([
                    {"type": "tool_use", "id": "toolu_4", "name": "Grep", "input": {"pattern": "fn main"}},
                ]),
            ),
            user(
                "r-4",
                "a-4",
                serde_json::json!([
                    {"type": "tool_result", "tool_use_id": "toolu_4", "content": "main.rs:1"},
                ]),
            ),
        ]);
        assert_eq!(messages, 8);
        assert_eq!(activities.len(), 4);

        let bash = &activities[0];
        assert_eq!(
            bash.message_native_id, "r-1",
            "活动锚定在携带 tool_result 的消息上"
        );
        assert_eq!(bash.activity.kind, ToolActivityKind::Command);
        assert_eq!(bash.activity.name, "Bash");
        assert_eq!(bash.activity.target.as_deref(), Some("ls -la"));
        assert_eq!(bash.activity.status, ToolActivityStatus::Success);
        assert_eq!(bash.activity.actor, ToolActivityActor::Main);

        let read = &activities[1];
        assert_eq!(read.activity.kind, ToolActivityKind::File);
        assert_eq!(read.activity.name, "Read");
        assert_eq!(read.activity.target.as_deref(), Some("src/main.rs"));
        assert_eq!(
            read.activity.status,
            ToolActivityStatus::Error,
            "is_error 如实映射"
        );
        assert_eq!(read.activity.actor, ToolActivityActor::Main);

        let web = &activities[2];
        assert_eq!(web.activity.kind, ToolActivityKind::Web);
        assert_eq!(
            web.activity.target.as_deref(),
            Some("https://example.test/docs")
        );
        // is_error 缺失 → 成功（设计 R4.2）。
        assert_eq!(web.activity.status, ToolActivityStatus::Success);

        let grep = &activities[3];
        assert_eq!(grep.activity.kind, ToolActivityKind::Query);
        assert_eq!(grep.activity.target.as_deref(), Some("fn main"));
    }

    #[test]
    fn parse_marks_unpaired_tool_use_as_unknown_status() {
        // 截断 transcript：tool_use 没有后续 tool_result → status Unknown，
        // 锚定在调用方消息（设计 R4.3/R5.1），绝不臆造结果。
        let (messages, activities) = parse_records(&[assistant(
            "a-unpaired",
            false,
            serde_json::json!([
                {"type": "tool_use", "id": "toolu_x", "name": "Bash", "input": {"command": "npm test"}},
            ]),
        )]);
        assert_eq!(messages, 1);
        assert_eq!(activities.len(), 1);
        assert_eq!(activities[0].message_native_id, "a-unpaired");
        assert_eq!(activities[0].activity.kind, ToolActivityKind::Command);
        assert_eq!(activities[0].activity.target.as_deref(), Some("npm test"));
        assert_eq!(activities[0].activity.status, ToolActivityStatus::Unknown);
    }

    #[test]
    fn parse_derives_subagent_actor_from_sidechain_caller() {
        let (_, activities) = parse_records(&[
            assistant(
                "a-sub",
                true,
                serde_json::json!([
                    {"type": "tool_use", "id": "toolu_s", "name": "Read", "input": {"file_path": "lib/util.rs"}},
                ]),
            ),
            user(
                "r-sub",
                "a-sub",
                serde_json::json!([
                    {"type": "tool_result", "tool_use_id": "toolu_s", "content": "ok"},
                ]),
            ),
        ]);
        assert_eq!(activities.len(), 1);
        assert_eq!(
            activities[0].activity.actor,
            ToolActivityActor::Subagent,
            "sidechain 调用方 → actor=subagent"
        );
    }

    #[test]
    fn parse_skips_orphan_tool_result_without_fabrication() {
        // tool_result 引用不存在的 tool_use_id：不透明（R6），静默跳过，
        // 不产出活动。
        let (messages, activities) = parse_records(&[user(
            "r-orphan",
            "a-1",
            serde_json::json!([
                {"type": "tool_result", "tool_use_id": "toolu_missing", "content": "who knows"},
            ]),
        )]);
        assert_eq!(messages, 1);
        assert!(activities.is_empty(), "孤儿 result 不得臆造活动");
    }

    #[test]
    fn parse_skips_opaque_tool_blocks() {
        // 无 name 的 tool_use 与无 id 的 tool_use 都是不透明记录（R6）：跳过。
        let (_, activities) = parse_records(&[assistant(
            "a-opaque",
            false,
            serde_json::json!([
                {"type": "tool_use", "id": "toolu_n", "input": {"command": "ls"}},
                {"type": "tool_use", "name": "Read", "input": {"file_path": "x.rs"}},
                {"type": "tool_use", "id": "toolu_ok", "name": "Bash", "input": {"command": "pwd"}},
            ]),
        )]);
        assert_eq!(
            activities.len(),
            1,
            "只有 id+name 齐全的调用登记 pending（EOF 以 Unknown 上报）"
        );
        assert_eq!(activities[0].activity.name, "Bash");
        assert_eq!(activities[0].activity.status, ToolActivityStatus::Unknown);
    }

    #[test]
    fn parse_unknown_tool_name_fails_closed() {
        // 名字不在已知闭集 → kind=unknown、target=None，即使 input 带了
        // 形似 command 的字段也不猜（设计 R2 第 6 条）。
        let (_, activities) = parse_records(&[
            assistant(
                "a-unk",
                false,
                serde_json::json!([
                    {"type": "tool_use", "id": "toolu_u", "name": "CustomThing", "input": {"command": "secret op"}},
                ]),
            ),
            user(
                "r-unk",
                "a-unk",
                serde_json::json!([
                    {"type": "tool_result", "tool_use_id": "toolu_u", "content": "ok"},
                ]),
            ),
        ]);
        assert_eq!(activities.len(), 1);
        assert_eq!(activities[0].activity.kind, ToolActivityKind::Unknown);
        assert_eq!(activities[0].activity.target, None);
        assert_eq!(activities[0].activity.status, ToolActivityStatus::Success);
    }
}
