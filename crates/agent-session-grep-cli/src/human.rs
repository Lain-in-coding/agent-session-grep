//! Human 渲染器：把成功结果投影为人类可读文本行（无 envelope、无颜色）。
//!
//! 见 `.trellis/tasks/07-26-human-robot-protocol/design.md` §2。
//! search/list/get/show/context/status/providers 各有专属版式，sync 与 ingest 各有统计
//! 版式，其余命令（index/index.rebuild/doctor/config.paths 及未知命令）共用
//! 同一条排序 `key: value` 兜底路径。约束：无颜色、无新依赖；任何输入不
//! panic——缺失或异常字段降级为 `?` 占位或空态措辞；每个返回元素都是单行
//! 可打印文本，无尾随空行。

use crate::protocol::{Outcome, Page};
use serde_json::Value;

/// `list` payload 预览的最大字符数（design §2）。
const LIST_PREVIEW_CHARS: usize = 60;
/// `context` 消息正文预览的最大字符数（design §2）。
const CONTEXT_TEXT_CHARS: usize = 80;
/// `search` 命中正文预览的最大字符数（10 角色体验测试缺陷修复：命中只有
/// UUID+score 时新手无从判断哪条有用）。
const SNIPPET_PREVIEW_CHARS: usize = 120;

/// 把成功结果渲染为人类可读行（无 envelope、无颜色）。
///
/// `data` 是 main.rs `render()` 为各命令构建的 JSON 形状（child 3 冻结）。
/// `outcome` 仅在 `data` 缺失截断元数据时兜底标注 partial；截断与续页
/// 提示以 `data.truncation` 与 `page` 为权威。
pub fn render_success(command: &str, outcome: Outcome, data: &Value, page: &Page) -> Vec<String> {
    match command {
        "search" => {
            let mut lines = render_search(data);
            push_footer(&mut lines, outcome, data, page);
            lines
        }
        "list" => {
            let mut lines = render_list(data);
            push_footer(&mut lines, outcome, data, page);
            lines
        }
        "context" => {
            let mut lines = render_context(data);
            push_footer(&mut lines, outcome, data, page);
            lines
        }
        "get" => render_get(data),
        "show" => render_show(data),
        "status" => render_status(data),
        "sync" => render_sync(data),
        "ingest" => render_ingest(data),
        "handoff" => render_handoff(data),
        "resume" => render_resume(data),
        "providers" => render_providers(data),
        "config.paths" => {
            // config paths 报告的是"默认位置"，未用到就不会创建；新手照着找会扑空
            // （10 角色体验测试缺陷）。加一句说明，结构本身保持稳定。
            let mut lines = kv_lines(data);
            lines.push("说明：以上是默认位置，未创建过的目录表示尚未使用，属正常。".into());
            lines
        }
        _ => kv_lines(data),
    }
}

/// `providers`：每个 provider 用两行展示成熟度/路线目标及完整逐字段能力。
/// `maturity_target: null`（deferred）与空 variant 都显示为破折号，不把未知目标
/// 伪装为当前事实。
fn render_providers(data: &Value) -> Vec<String> {
    let providers = data
        .get("providers")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default();
    if providers.is_empty() {
        return vec!["providers: none".into()];
    }

    let field = |provider: &Value, key: &str| {
        provider
            .get(key)
            .and_then(Value::as_str)
            .map(sanitize)
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| MISSING.into())
    };
    let mut lines = Vec::with_capacity(1 + providers.len() * 2);
    lines.push(format!("providers: {}", providers.len()));
    for provider in providers {
        lines.push(format!(
            "{}  maturity={}  target={}  variant={}",
            field(provider, "provider_id"),
            field(provider, "maturity"),
            field(provider, "maturity_target"),
            field(provider, "variant_id"),
        ));
        lines.push(format!(
            "  discover={} probe={} parse={} search={} context={} resume={} handoff={} tool_activity={} source_span={} incremental={}",
            field(provider, "discover"),
            field(provider, "probe"),
            field(provider, "parse"),
            field(provider, "search"),
            field(provider, "context"),
            field(provider, "resume"),
            field(provider, "handoff"),
            field(provider, "tool_activity"),
            field(provider, "source_span"),
            field(provider, "incremental"),
        ));
    }
    lines
}

/// `resume`：dry-run 预览把要执行的命令摊开给人看——可恢复性、完整命令、
/// 原工作目录、权限模式，以及是否已执行。不可恢复时给出原因与措辞，
/// 不打印空命令行。
fn render_resume(data: &Value) -> Vec<String> {
    let mut lines = Vec::new();
    let session = data
        .get("session_id")
        .and_then(Value::as_str)
        .map(sanitize)
        .unwrap_or_else(|| "?".into());
    let provider = data
        .get("provider_id")
        .and_then(Value::as_str)
        .map(sanitize)
        .unwrap_or_else(|| MISSING.into());
    lines.push(format!("session {session}  (provider {provider})"));

    let available = data
        .get("available")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if !available {
        let reason = data
            .get("unavailable_reason")
            .and_then(Value::as_str)
            .map(sanitize)
            .unwrap_or_else(|| "未记录原因".into());
        lines.push(format!("不可恢复：{reason}"));
        lines.push("说明：历史仍可检索，只是无法原地恢复。".into());
        return lines;
    }

    let command = data
        .get("command")
        .and_then(Value::as_str)
        .map(sanitize)
        .unwrap_or_else(|| "?".into());
    lines.push(format!("命令：{command}"));
    if let Some(dir) = data.get("working_directory").and_then(Value::as_str) {
        lines.push(format!("工作目录：{}", sanitize(dir)));
    }
    // 权限模式恒如实标注：未核验时明示"未核验"，绝不静默省略（audit P1-2）。
    let permission_mode = data
        .get("permission_mode")
        .and_then(Value::as_str)
        .map(sanitize);
    let permission_verified = data
        .get("permission_mode_verified")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    match permission_mode {
        Some(mode) => lines.push(format!("权限模式：{}", mode)),
        None if permission_verified => lines.push("权限模式：默认（无 yolo/full-auto）".into()),
        None => lines.push("权限模式：未核验（默认不带，不自动加 yolo/full-auto）".into()),
    }
    let executed = data
        .get("executed")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if executed {
        lines.push("已执行：provider 进程已启动并退出。".into());
    } else if data
        .get("first_run_preview")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        lines.push("首次使用：已强制预览未执行（--yes 已被忽略）。再次运行 resume --yes 确认后才会真正执行。".into());
    } else {
        lines.push("dry-run：未执行。加 --yes 实际恢复。".into());
    }
    lines
}

/// `handoff`：把 handoff pack 投影为可读分栏——pack 元信息、matched
/// sessions、原文证据（evidence）、推断（inference）与预算/截断状态。
/// 任何字段缺失都降级为 `?` 或空态措辞（与其余渲染器同一约束）。
fn render_handoff(data: &Value) -> Vec<String> {
    let mut lines = Vec::new();
    let pack_id = data
        .get("pack_id")
        .and_then(Value::as_str)
        .map(sanitize)
        .unwrap_or_else(|| "?".into());
    let created_at = data
        .get("created_at")
        .and_then(Value::as_str)
        .map(sanitize)
        .unwrap_or_else(|| "?".into());
    let generation = number_text(data, "catalog_generation");
    let schema_version = data
        .get("schema_version")
        .and_then(Value::as_str)
        .unwrap_or("?");
    lines.push(format!(
        "handoff pack {pack_id} (schema {schema_version}; generation {generation})"
    ));
    lines.push(format!("created_at: {created_at}"));

    let confidence = data
        .get("confidence")
        .and_then(|c| c.get("overall"))
        .and_then(Value::as_str)
        .unwrap_or("?");
    lines.push(format!("confidence: {confidence}"));

    // Matched sessions: id + occurrences.
    let matched = data
        .get("matched_sessions")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default();
    if matched.is_empty() {
        lines.push("matched_sessions: none".into());
    } else {
        lines.push(format!("matched_sessions: {}", matched.len()));
        for session in matched {
            let id = session
                .get("session_id")
                .and_then(Value::as_str)
                .map(sanitize)
                .unwrap_or_else(|| "?".into());
            let occurrences = session
                .get("occurrences")
                .and_then(Value::as_u64)
                .unwrap_or(1);
            lines.push(format!("  {id}  ({occurrences} occurrence(s))"));
        }
    }

    // Evidence: original text spans, one line each (truncated preview).
    let evidence = data
        .get("evidence")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default();
    lines.push(format!("evidence: {}", evidence.len()));
    for entry in evidence {
        let text = entry
            .get("text")
            .and_then(Value::as_str)
            .map(|text| preview(text, CONTEXT_TEXT_CHARS))
            .unwrap_or_default();
        let id = entry
            .get("message_id")
            .and_then(Value::as_str)
            .map(sanitize)
            .unwrap_or_else(|| "?".into());
        lines.push(format!("  [{id}] {text}"));
    }

    // Inference: deterministic generator emits none; render honestly.
    let inference = data
        .get("inference")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default();
    if inference.is_empty() {
        lines.push("inference: none (deterministic)".into());
    } else {
        lines.push(format!("inference: {}", inference.len()));
        for entry in inference {
            let text = entry
                .get("text")
                .and_then(Value::as_str)
                .map(|text| preview(text, CONTEXT_TEXT_CHARS))
                .unwrap_or_default();
            lines.push(format!("  {text}"));
        }
    }

    // Truncation: only surface when the pack is incomplete.
    if let Some(truncation) = data.get("truncation") {
        let truncated = truncation
            .get("truncated")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if truncated {
            let reason = truncation
                .get("reason")
                .and_then(Value::as_str)
                .unwrap_or("?");
            let dropped = truncation
                .get("dropped_count")
                .and_then(Value::as_u64)
                .unwrap_or(0);
            lines.push(format!("truncated: reason={reason} dropped={dropped}"));
        }
    }
    lines
}

/// `search`：头行 `N hit(s) (generation G)` + 每命中 `  <rank>. <id>  score <s>`，
/// 若命中有正文预览（human 渲染前由 CLI 附加）则追加一行缩进的片段；
/// 零命中给措辞 `no hits` 并提示换词。
fn render_search(data: &Value) -> Vec<String> {
    if let Some(rows) = data.get("session_resume_rows").and_then(Value::as_array)
        && !rows.is_empty()
    {
        let rows: Vec<SessionResumeTableRow> = rows
            .iter()
            .map(|row| SessionResumeTableRow {
                date_ymd: row
                    .get("date")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
                provider: row
                    .get("provider")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
                title: row.get("title").and_then(Value::as_str).map(str::to_string),
                working_directory: row
                    .get("working_directory")
                    .and_then(Value::as_str)
                    .map(str::to_string),
                session_id: row
                    .get("session_id")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
            })
            .collect();
        return render_session_resume_table(&rows)
            .lines()
            .map(str::to_string)
            .collect();
    }
    let hits = data
        .get("hits")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default();
    if hits.is_empty() {
        return vec![
            "no hits".into(),
            "提示：试试更短或更少的关键词（如只搜一个词）。".into(),
        ];
    }
    let mut lines = vec![format!(
        "{} hit(s) (generation {})",
        hits.len(),
        number_text(data, "generation")
    )];
    for (index, hit) in hits.iter().enumerate() {
        let id = hit
            .get("id")
            .and_then(Value::as_str)
            .map(sanitize)
            .unwrap_or_else(|| "?".into());
        let score = hit
            .get("score")
            .and_then(Value::as_f64)
            .map(|score| format!("{score:.2}"))
            .unwrap_or_else(|| "?".into());
        lines.push(format!("  {}. {id}  score {score}", index + 1));
        // 正文预览：命中是否有用一瞥即知。取不到 preview 的命中不补行。
        // ADR-0008 后摘要统一由命中对象的 `text` 字段承载（application 装配，
        // 按 max_snippet_chars 截前缀）；`snippet` 是旧字段名，为兼容旧形状
        // 仍作为回退读取。两者都不存在则省略该行。
        if let Some(text) = hit
            .get("snippet")
            .or_else(|| hit.get("text"))
            .and_then(Value::as_str)
            .map(|text| preview(text, SNIPPET_PREVIEW_CHARS))
            && !text.is_empty()
        {
            lines.push(format!("     {text}"));
        }
    }
    lines
}

/// `list`：头行 `N entrie(s) (generation G)` + 每条 `  <id>  <payload 预览>`；
/// 零条目给措辞 `catalog is empty`。
fn render_list(data: &Value) -> Vec<String> {
    let entries = data
        .get("entries")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default();
    if entries.is_empty() {
        return vec!["catalog is empty".into()];
    }
    let mut lines = vec![format!(
        "{} entries (generation {})",
        entries.len(),
        number_text(data, "generation")
    )];
    for entry in entries {
        let id = entry
            .get("id")
            .and_then(Value::as_str)
            .map(sanitize)
            .unwrap_or_else(|| "?".into());
        let payload = entry
            .get("payload")
            .and_then(Value::as_str)
            .map(|payload| preview(payload, LIST_PREVIEW_CHARS))
            .unwrap_or_else(|| "?".into());
        lines.push(format!("  {id}  {payload}"));
    }
    lines
}

/// `get`：payload 字符串原样逐行输出（尾部空白行剔除，保证无尾随空行）；
/// null 或缺失 → `not found`。
fn render_get(data: &Value) -> Vec<String> {
    match data.get("payload") {
        None | Some(Value::Null) => vec!["not found".into()],
        Some(Value::String(payload)) => {
            let mut lines: Vec<String> = payload.lines().map(str::to_string).collect();
            while lines.last().is_some_and(|line| line.trim().is_empty()) {
                lines.pop();
            }
            lines
        }
        Some(other) => vec![value_inline(other)],
    }
}

/// `show`：消息实体（payload 带 `role`/`text`）只展示新手关心的字段
/// （role/text/timestamp/session），内部结构（span/placement/fingerprint）留给
/// json 模式——新手看到整墙内部字段无从下手（10 角色体验测试缺陷）；会话/文档
/// 等容器实体没有这些字段，退回按顶层字段展开的通用 `key: value` 版式：不套
/// 消息投影、不补 `?`、不编造 `context` 提示。null 或缺失 → `not found`。
fn render_show(data: &Value) -> Vec<String> {
    match data.get("entity") {
        None | Some(Value::Null) => vec!["not found".into()],
        Some(entity) if is_message_entity(entity) => {
            let role = entity
                .get("role")
                .and_then(Value::as_str)
                .map(sanitize)
                .unwrap_or_else(|| "?".into());
            let timestamp = entity
                .get("timestamp")
                .and_then(Value::as_str)
                .map(sanitize)
                .unwrap_or_else(|| "?".into());
            let session = entity.get("session").and_then(Value::as_str).map(sanitize);
            let text = entity
                .get("text")
                .and_then(Value::as_str)
                .map(sanitize)
                .unwrap_or_else(|| "?".into());
            let mut lines = vec![
                format!("role: {role}"),
                format!("timestamp: {timestamp}"),
                format!("session: {}", session.as_deref().unwrap_or("?")),
                format!("text: {text}"),
            ];
            // 会话引用未知时 `context <session>` 提示无从执行，不渲染。
            if session.is_some() {
                lines.push("用 context <session> 展开这个会话的完整上下文。".into());
            }
            lines
        }
        Some(entity) => kv_lines(entity),
    }
}

/// 消息实体判定：消息 payload 恒带 `role`（非 JSON 的兜底形状为
/// `role`/`text`）；会话/文档容器 payload 没有这两个字段。
fn is_message_entity(entity: &Value) -> bool {
    entity.get("role").is_some() || entity.get("text").is_some()
}

/// `context`：会话头行 + 编号消息（role/text 取自各消息 payload，缺失 → `?`）
/// + 证据计数行 `evidence: N span(s)`。
fn render_context(data: &Value) -> Vec<String> {
    let session_id = data
        .get("session_id")
        .and_then(Value::as_str)
        .map(sanitize)
        .unwrap_or_else(|| "?".into());
    let leaf = data
        .get("branch_leaf")
        .and_then(Value::as_str)
        .map(sanitize)
        .unwrap_or_else(|| "none".into());
    let mut lines = vec![format!(
        "session {session_id}  branch leaf {leaf}  (generation {})",
        number_text(data, "generation")
    )];
    let messages = data
        .get("messages")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default();
    for (index, message) in messages.iter().enumerate() {
        let payload = message.get("payload");
        let role = payload
            .and_then(|payload| payload.get("role"))
            .and_then(Value::as_str)
            .map(sanitize)
            .unwrap_or_else(|| "?".into());
        // 截断时给出真实消息 wire id，`show <id>` 提示可直接复制执行
        // （10 角色体验测试缺陷：context 静默截断到 80 字符无标记，且提示里
        // `<id>` 只是占位符）。
        let wire_id = message
            .get("message_id")
            .or_else(|| message.get("id"))
            .and_then(Value::as_str)
            .map(sanitize);
        let text = payload
            .and_then(|payload| payload.get("text"))
            .and_then(Value::as_str)
            .map(|text| {
                if text.chars().count() > CONTEXT_TEXT_CHARS {
                    let truncated = preview(text, CONTEXT_TEXT_CHARS);
                    match &wire_id {
                        Some(wire_id) => {
                            format!("{truncated}…(已截断,用 show {wire_id} 看全文)")
                        }
                        None => format!("{truncated}…(已截断)"),
                    }
                } else {
                    preview(text, CONTEXT_TEXT_CHARS)
                }
            })
            .unwrap_or_else(|| "?".into());
        lines.push(format!("  {}. [{role}] {text}", index + 1));
    }
    match data.get("evidence").and_then(Value::as_array) {
        Some(evidence) => lines.push(format!("evidence: {} span(s)", evidence.len())),
        None => lines.push("evidence: ? span(s)".into()),
    }
    lines
}

/// `status`：`entities: N` + `generation: G` 两行。
fn render_status(data: &Value) -> Vec<String> {
    vec![
        format!("entities: {}", number_text(data, "catalog_count")),
        format!("generation: {}", number_text(data, "generation")),
    ]
}

/// `sync`/`ingest`：字段统计 + 一句人话总结。unchanged 是消息条数而非文件数，
/// 新手会把 882 读成文件数而困惑（10 角色体验测试缺陷）；这里显式标注单位，
/// 并给出"新增/无变化"的结论行。
fn render_sync(data: &Value) -> Vec<String> {
    let num = |key: &str| number_text(data, key);
    let mut lines = vec![
        format!("sources: {}（本次扫描的源文件数）", num("sources")),
        format!("emitted: {}（本次新解析的消息条数）", num("emitted")),
        format!(
            "unchanged: {}（未变化的已有消息条数，不是文件数）",
            num("unchanged")
        ),
        format!("skipped: {}（因格式无法入库的消息条数）", num("skipped")),
        format!("generation: {}（当前入库代次）", num("generation")),
    ];
    let unchanged = data.get("unchanged").and_then(Value::as_u64);
    let emitted = data.get("emitted").and_then(Value::as_u64);
    match (emitted, unchanged) {
        (Some(0), Some(_)) => lines.push("总结：没有新增消息（源文件未变化）。".into()),
        (Some(e), Some(_)) => lines.push(format!("总结：新增 {e} 条消息。")),
        _ => {}
    }
    lines
}

/// `ingest`：单文件入库的专属版式。ingest 只解析一个文件，`sources` 恒为 1；
/// 不复用 sync 的统计版式——ingest 响应里没有 `sources` 字段，旧实现会渲染
/// 出 `sources: ?`。只渲染响应实际携带的字段（variant/source_fp/committed/
/// diagnostics），缺失的字段不补 `?` 也不显示。
fn render_ingest(data: &Value) -> Vec<String> {
    let mut lines = vec!["sources: 1（本次扫描的源文件数）".into()];
    if let Some(variant) = data.get("variant").and_then(Value::as_str) {
        lines.push(format!("variant: {}", sanitize(variant)));
    }
    if let Some(source_fp) = data.get("source_fp").and_then(Value::as_str) {
        lines.push(format!("source_fp: {}", sanitize(source_fp)));
    }
    if let Some(committed) = data.get("committed").and_then(Value::as_u64) {
        lines.push(format!("committed: {committed}（本次新入库的消息条数）"));
    }
    if let Some(diagnostics) = data.get("diagnostics").and_then(Value::as_u64) {
        lines.push(format!("diagnostics: {diagnostics}（解析诊断条数）"));
    }
    // 与 sync 一致给结论行；ingest 的"新增"以 committed（实际入库数）为准：
    // 重复 ingest 未变化的文件时 committed 为 0。
    match data.get("committed").and_then(Value::as_u64) {
        Some(0) => lines.push("总结：没有新增消息（源文件未变化）。".into()),
        Some(count) => lines.push(format!("总结：新增 {count} 条消息。")),
        None => {}
    }
    lines
}

/// 截断与续页提示行。`data.truncation` 为权威；元数据缺失但 outcome 已声明
/// partial 时仍以 `?` 占位暴露截断事实。续页行要求 has_more 且携带令牌。
fn push_footer(lines: &mut Vec<String>, outcome: Outcome, data: &Value, page: &Page) {
    let truncation = data.get("truncation");
    let truncated = truncation
        .and_then(|truncation| truncation.get("truncated"))
        .and_then(Value::as_bool);
    if truncated == Some(true) {
        let reason = truncation
            .and_then(|truncation| truncation.get("reason"))
            .and_then(Value::as_str)
            .map(sanitize)
            .unwrap_or_else(|| "?".into());
        lines.push(format!("truncated: {reason}"));
    } else if truncated.is_none() && matches!(outcome, Outcome::Partial) {
        lines.push("truncated: ?".into());
    }
    if let Some(token) = page.next_cursor.as_deref().filter(|_| page.has_more) {
        // 新手会把超长 cursor 误判为报错或结果只有一页（10 角色体验测试缺陷）。
        // 明确告知"还有结果"并给出可直接复制的完整命令。
        lines.push(
            "还有更多结果：复制下面这行追加 --cursor 即可翻页（cursor 约 15 分钟有效）".into(),
        );
        lines.push(format!("  --cursor {token}"));
    }
}

/// 兜底路径：对象展开为按 key 排序的 `key: value` 行（嵌套值紧凑 JSON）；
/// 非对象输入降级为单行内联值。所有无专属版式的命令共用此函数。
fn kv_lines(data: &Value) -> Vec<String> {
    match data.as_object() {
        Some(map) => {
            let mut pairs: Vec<(&String, &Value)> = map.iter().collect();
            pairs.sort_by_key(|(key, _)| *key);
            pairs
                .into_iter()
                .map(|(key, value)| format!("{}: {}", sanitize(key), value_inline(value)))
                .collect()
        }
        None => vec![value_inline(data)],
    }
}

/// 值的单行内联展示：字符串裸出（压成单行），其余值一律紧凑 JSON
/// （serde_json 会转义控制字符，天然单行）。
fn value_inline(value: &Value) -> String {
    match value {
        Value::String(text) => sanitize(text),
        other => other.to_string(),
    }
}

/// 数字字段的展示文本；缺失或非数字降级为 `?`。
fn number_text(data: &Value, key: &str) -> String {
    match data.get(key) {
        Some(Value::Number(number)) => number.to_string(),
        _ => "?".into(),
    }
}

/// 单行化预览：控制字符替换为空格，超出 `max` 字符即截断（字符边界安全）。
fn preview(text: &str, max: usize) -> String {
    text.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .take(max)
        .collect()
}

/// 仅单行化、不截断。
fn sanitize(text: &str) -> String {
    preview(text, usize::MAX)
}

/// Session Resume 表格的一行（human 渲染专用；值由 main.rs 装配，`date_ymd`
/// 已格式化为本地 `YYYY-MM-DD`）。
pub struct SessionResumeTableRow {
    pub date_ymd: String,
    pub provider: String,
    pub title: Option<String>,
    pub working_directory: Option<String>,
    pub session_id: String,
}

/// 表格目标总宽：日期/Provider/Session ID 按内容占满后，标题与工作目录在
/// 剩余预算内按 35%/65% 分配；预算不足时保留最小列宽，整体超宽交给终端换行。
const TABLE_TARGET_COLS: usize = 100;
/// 标题列最小显示宽度。
const TITLE_MIN_COLS: usize = 12;
/// 工作目录列最小显示宽度。
const CWD_MIN_COLS: usize = 16;
/// 列间隔 ` | ` 的显示宽度。
const COL_GAP_COLS: usize = 3;
/// 缺失值占位符。
const MISSING: &str = "—";

/// 清洗后的单行单元格（缺失值已统一替换为 `—`）。
struct PreparedResumeRow {
    date: String,
    provider: String,
    title: String,
    working_directory: String,
    session_id: String,
}

/// 渲染一组会话 Resume 元数据为横向表格（ADR-0009）：
/// `日期 | Provider | 会话标题 | 工作目录 | Session ID`。
///
/// - Provider 与 Session ID 永不截断；标题超长尾部省略（`…`）、工作目录超长
///   中间折叠（如 `C:/…/agent-session-grep`）；缺失值统一渲染 `—`；
///   newline/tab 清洗为空格；CJK 按显示宽度 2 对齐。
/// - 宽度不足时不切换纵向版式：行保持完整、字段值不截断，超宽由终端换行。
pub fn render_session_resume_table(rows: &[SessionResumeTableRow]) -> String {
    if rows.is_empty() {
        return String::new();
    }
    let cells: Vec<PreparedResumeRow> = rows.iter().map(prepare_resume_row).collect();
    let date_width = display_width("日期")
        .max(10)
        .max(widest(&cells, |cell| &cell.date));
    let provider_width = display_width("Provider").max(widest(&cells, |cell| &cell.provider));
    let session_width = display_width("Session ID").max(widest(&cells, |cell| &cell.session_id));
    let fixed_cols = date_width + provider_width + session_width + COL_GAP_COLS * 4;
    let remaining = TABLE_TARGET_COLS.saturating_sub(fixed_cols);
    let title_width = TITLE_MIN_COLS.max(remaining * 35 / 100);
    let cwd_width = CWD_MIN_COLS.max(remaining * 65 / 100);

    let mut lines = vec![format!(
        "{} | {} | {} | {} | Session ID",
        pad_to_width("日期", date_width),
        pad_to_width("Provider", provider_width),
        pad_to_width("会话标题", title_width),
        pad_to_width("工作目录", cwd_width),
    )];
    for cell in &cells {
        lines.push(format!(
            "{} | {} | {} | {} | {}",
            pad_to_width(&cell.date, date_width),
            pad_to_width(&cell.provider, provider_width),
            pad_to_width(
                &truncate_tail_ellipsis(&cell.title, title_width),
                title_width
            ),
            pad_to_width(
                &collapse_middle(&cell.working_directory, cwd_width),
                cwd_width
            ),
            cell.session_id,
        ));
    }
    lines.join("\n")
}

/// 各单元格的最大显示宽度。
fn widest(cells: &[PreparedResumeRow], key: impl Fn(&PreparedResumeRow) -> &str) -> usize {
    cells.iter().map(key).map(display_width).max().unwrap_or(0)
}

/// 清洗单元格并统一缺失值：控制字符替换为空格，空白（含空串）渲染 `—`。
fn prepare_resume_row(row: &SessionResumeTableRow) -> PreparedResumeRow {
    PreparedResumeRow {
        date: cell_text(&row.date_ymd),
        provider: cell_text(&row.provider),
        title: row
            .title
            .as_deref()
            .map(cell_text)
            .unwrap_or_else(|| MISSING.into()),
        working_directory: row
            .working_directory
            .as_deref()
            .map(cell_text)
            .unwrap_or_else(|| MISSING.into()),
        session_id: cell_text(&row.session_id),
    }
}

/// 单元格文本：控制字符清洗为空格；空白视为缺失，统一渲染 `—`。
fn cell_text(raw: &str) -> String {
    let text = sanitize(raw);
    if text.trim().is_empty() {
        MISSING.into()
    } else {
        text
    }
}

/// 按显示宽度右填充空格至 `width` 列；已超宽时原样返回（不截断）。
fn pad_to_width(text: &str, width: usize) -> String {
    let used = display_width(text);
    if used >= width {
        text.to_string()
    } else {
        format!("{text}{}", " ".repeat(width - used))
    }
}

/// 尾部省略：超出 `max_width` 时按显示宽度截前缀并接 `…`（占 1 列）。
fn truncate_tail_ellipsis(text: &str, max_width: usize) -> String {
    let text = sanitize(text);
    if display_width(&text) <= max_width {
        return text;
    }
    let prefix = take_display_prefix(&text, max_width.saturating_sub(1));
    format!("{prefix}…")
}

/// 工作目录中间折叠：保留首段与尾段、中间接 `…`（如 `C:/…/agent-session-grep`）；
/// 单段路径或预算过小退化为字符级中间折叠。
fn collapse_middle(text: &str, max_width: usize) -> String {
    let text = sanitize(text);
    if display_width(&text) <= max_width {
        return text;
    }
    let parts: Vec<&str> = text.split(&['/', '\\'][..]).collect();
    if parts.len() <= 1 || max_width <= 3 {
        return char_fold_middle(&text, max_width);
    }
    let head_budget = (max_width - 3) / 2;
    let tail_budget = max_width - 3 - head_budget;
    let mut head: Vec<&str> = Vec::new();
    let mut head_used = 0usize;
    for (index, part) in parts.iter().enumerate() {
        let cost = display_width(part) + usize::from(index > 0);
        if index > 0 && head_used + cost > head_budget {
            break;
        }
        head_used += cost;
        head.push(part);
    }
    let mut tail: Vec<&str> = Vec::new();
    let mut tail_used = 0usize;
    for (offset, part) in parts.iter().rev().enumerate() {
        let cost = display_width(part) + 1;
        if offset > 0 && tail_used + cost > tail_budget {
            break;
        }
        tail_used += cost;
        tail.push(part);
    }
    let mut tail: Vec<&str> = tail.into_iter().rev().collect();
    if head.len() + tail.len() > parts.len() {
        tail.truncate(parts.len() - head.len());
    }
    let sep = text
        .chars()
        .find(|c| matches!(c, '/' | '\\'))
        .unwrap_or('/');
    let head_text = head.join(&sep.to_string());
    if tail.is_empty() {
        return format!("{head_text}{sep}…");
    }
    let tail_text = tail.join(&sep.to_string());
    format!("{head_text}{sep}…{sep}{tail_text}")
}

/// 字符级中间折叠：前缀 + `…` + 后缀（单段路径或极小预算的退路）。
fn char_fold_middle(text: &str, max_width: usize) -> String {
    let prefix_width = max_width.saturating_sub(1) / 2;
    let suffix_width = max_width.saturating_sub(1) - prefix_width;
    let prefix = take_display_prefix(text, prefix_width);
    let suffix = take_display_suffix(text, suffix_width);
    format!("{prefix}…{suffix}")
}

/// 按显示宽度取前缀，字符边界安全。
fn take_display_prefix(text: &str, max_width: usize) -> String {
    let mut prefix = String::new();
    let mut used = 0usize;
    for c in text.chars() {
        let width = char_display_width(c);
        if used + width > max_width {
            break;
        }
        used += width;
        prefix.push(c);
    }
    prefix
}

/// 按显示宽度取后缀（从尾部累计，再恢复原顺序）。
fn take_display_suffix(text: &str, max_width: usize) -> String {
    let mut suffix: Vec<char> = Vec::new();
    let mut used = 0usize;
    for c in text.chars().rev() {
        let width = char_display_width(c);
        if used + width > max_width {
            break;
        }
        used += width;
        suffix.push(c);
    }
    suffix.into_iter().rev().collect()
}

/// 字符串显示宽度：CJK（统一表意文字、假名、谚文、全角形式等）按 2 列计。
fn display_width(text: &str) -> usize {
    text.chars().map(char_display_width).sum()
}

/// 单字符显示宽度：CJK 及其兼容形式按 2 列计，其余按 1 列计。
fn char_display_width(c: char) -> usize {
    let code = c as u32;
    if (0x1100..=0x115F).contains(&code) // 谚文字母
        || (0x2E80..=0x303E).contains(&code) // CJK 部首与标点
        || (0x3041..=0x33FF).contains(&code) // 假名、CJK 兼容
        || (0x3400..=0x4DBF).contains(&code) // CJK 扩展 A
        || (0x4E00..=0x9FFF).contains(&code) // CJK 统一表意文字
        || (0xA000..=0xA4CF).contains(&code) // 彝文
        || (0xAC00..=0xD7A3).contains(&code) // 谚文音节
        || (0xF900..=0xFAFF).contains(&code) // CJK 兼容表意文字
        || (0xFE30..=0xFE4F).contains(&code) // CJK 兼容形式
        || (0xFF00..=0xFF60).contains(&code) // 全角形式
        || (0xFFE0..=0xFFE6).contains(&code)
    // 全角符号
    {
        2
    } else {
        1
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn page_more(token: &str) -> Page {
        Page {
            next_cursor: Some(token.into()),
            has_more: true,
        }
    }

    #[test]
    fn providers_renders_maturity_target_and_all_capabilities() {
        let data = json!({
            "providers": [{
                "provider_id": "claude-code",
                "variant_id": "claude-code/jsonl-v1",
                "maturity": "experimental",
                "maturity_target": "certified",
                "discover": "native",
                "probe": "native",
                "parse": "native",
                "search": "native",
                "context": "native",
                "resume": "derived",
                "handoff": "unsupported",
                "tool_activity": "partial",
                "source_span": "native",
                "incremental": "native"
            }, {
                "provider_id": "zcode",
                "variant_id": "",
                "maturity": "unsupported",
                "maturity_target": null,
                "discover": "unknown",
                "probe": "unknown",
                "parse": "unknown",
                "search": "unknown",
                "context": "unknown",
                "resume": "unknown",
                "handoff": "unknown",
                "tool_activity": "unknown",
                "source_span": "unknown",
                "incremental": "unknown"
            }]
        });
        let lines = render_success("providers", Outcome::Success, &data, &Page::default());
        assert_eq!(lines.len(), 5);
        assert_eq!(lines[0], "providers: 2");
        assert!(lines[1].contains("maturity=experimental"), "{lines:?}");
        assert!(lines[1].contains("target=certified"), "{lines:?}");
        assert!(lines[2].contains("tool_activity=partial"), "{lines:?}");
        assert!(lines[3].contains("target=—"), "{lines:?}");
        assert!(lines[3].contains("variant=—"), "{lines:?}");
        assert!(lines[4].contains("incremental=unknown"), "{lines:?}");
    }

    #[test]
    fn resume_renders_dry_run_preview() {
        let data = json!({
            "session_id": "ses_v1_aaa",
            "provider_id": "claude-code",
            "available": true,
            "command": "(cd /home/u/proj && claude --resume abc-123)",
            "working_directory": "/home/u/proj",
            "permission_mode": null,
            "permission_mode_verified": false,
            "unavailable_reason": null,
            "executed": false,
        });
        let lines = render_success("resume", Outcome::Success, &data, &Page::default());
        assert_eq!(
            lines,
            [
                "session ses_v1_aaa  (provider claude-code)",
                "命令：(cd /home/u/proj && claude --resume abc-123)",
                "工作目录：/home/u/proj",
                "权限模式：未核验（默认不带，不自动加 yolo/full-auto）",
                "dry-run：未执行。加 --yes 实际恢复。",
            ]
        );
    }

    #[test]
    fn resume_renders_first_run_forced_preview() {
        let data = json!({
            "session_id": "ses_v1_ddd",
            "provider_id": "codex",
            "available": true,
            "command": "codex resume xyz",
            "working_directory": null,
            "permission_mode": null,
            "permission_mode_verified": false,
            "unavailable_reason": null,
            "executed": false,
            "first_run_preview": true,
        });
        let lines = render_success("resume", Outcome::Success, &data, &Page::default());
        assert!(
            lines
                .iter()
                .any(|l| l.starts_with("首次使用：已强制预览未执行")),
            "{lines:?}"
        );
        assert!(
            lines.iter().any(|l| l.contains("--yes 已被忽略")),
            "{lines:?}"
        );
    }

    #[test]
    fn resume_renders_unavailable_without_command_line() {
        let data = json!({
            "session_id": "ses_v1_bbb",
            "provider_id": null,
            "available": false,
            "command": null,
            "working_directory": null,
            "permission_mode": null,
            "unavailable_reason": "no resume metadata claims",
            "executed": false,
        });
        let lines = render_success("resume", Outcome::Success, &data, &Page::default());
        assert_eq!(
            lines,
            [
                "session ses_v1_bbb  (provider —)",
                "不可恢复：no resume metadata claims",
                "说明：历史仍可检索，只是无法原地恢复。",
            ]
        );
    }

    #[test]
    fn resume_renders_executed_state() {
        let data = json!({
            "session_id": "ses_v1_ccc",
            "provider_id": "codex",
            "available": true,
            "command": "codex resume xyz",
            "working_directory": null,
            "permission_mode": "--dangerously-bypass-approvals-and-sandbox",
            "unavailable_reason": null,
            "executed": true,
        });
        let lines = render_success("resume", Outcome::Success, &data, &Page::default());
        assert!(
            lines
                .iter()
                .any(|l| l == "已执行：provider 进程已启动并退出。")
        );
        assert!(
            lines
                .iter()
                .any(|l| l == "权限模式：--dangerously-bypass-approvals-and-sandbox")
        );
    }

    #[test]
    fn handoff_renders_sections_and_schema() {
        let data = json!({
            "pack_id": "pack_v1_abcd1234",
            "schema_version": "1.0",
            "catalog_generation": 3,
            "created_at": "2026-08-16T01:00:00Z",
            "confidence": { "overall": "high" },
            "matched_sessions": [
                { "session_id": "ses_v1_aaa", "occurrences": 2 }
            ],
            "evidence": [
                { "message_id": "msg_v1_aaa", "text": "the real evidence text" }
            ],
            "inference": [],
            "truncation": { "truncated": false, "reason": "none", "dropped_count": 0 },
        });
        let lines = render_success("handoff", Outcome::Success, &data, &Page::default());
        assert_eq!(
            lines,
            [
                "handoff pack pack_v1_abcd1234 (schema 1.0; generation 3)",
                "created_at: 2026-08-16T01:00:00Z",
                "confidence: high",
                "matched_sessions: 1",
                "  ses_v1_aaa  (2 occurrence(s))",
                "evidence: 1",
                "  [msg_v1_aaa] the real evidence text",
                "inference: none (deterministic)",
            ]
        );
    }

    #[test]
    fn handoff_renders_truncation_when_incomplete() {
        let data = json!({
            "pack_id": "pack_v1_x",
            "schema_version": "1.0",
            "catalog_generation": 1,
            "created_at": "2026-08-16T01:00:00Z",
            "confidence": { "overall": "low" },
            "matched_sessions": [],
            "evidence": [],
            "inference": [],
            "truncation": { "truncated": true, "reason": "max_evidence", "dropped_count": 9 },
        });
        let lines = render_success("handoff", Outcome::Success, &data, &Page::default());
        assert!(
            lines
                .iter()
                .any(|l| l.starts_with("matched_sessions: none"))
        );
        assert!(
            lines
                .iter()
                .any(|l| l == "truncated: reason=max_evidence dropped=9")
        );
    }

    #[test]
    fn search_renders_ranked_hits_with_generation_header() {
        let data = json!({
            "hits": [
                { "id": "msg_v1_aaaa", "score": 1.234 },
                { "id": "msg_v1_bbbb", "score": 0.5 },
            ],
            "generation": 7,
            "truncation": { "truncated": false, "reason": null },
        });
        let lines = render_success("search", Outcome::Success, &data, &Page::default());
        assert_eq!(
            lines,
            [
                "2 hit(s) (generation 7)",
                "  1. msg_v1_aaaa  score 1.23",
                "  2. msg_v1_bbbb  score 0.50",
            ]
        );
    }

    #[test]
    fn search_zero_hits_is_worded() {
        let data = json!({
            "hits": [],
            "generation": 1,
            "truncation": { "truncated": false, "reason": null },
        });
        let lines = render_success("search", Outcome::Success, &data, &Page::default());
        assert_eq!(
            lines,
            ["no hits", "提示：试试更短或更少的关键词（如只搜一个词）。",]
        );
    }

    #[test]
    fn search_appends_truncation_and_cursor_hint() {
        let data = json!({
            "hits": [{ "id": "msg_v1_aaaa", "score": 2.0 }],
            "generation": 3,
            "truncation": { "truncated": true, "reason": "max_items" },
        });
        let lines = render_success("search", Outcome::Partial, &data, &page_more("tok.abc"));
        assert_eq!(
            lines,
            [
                "1 hit(s) (generation 3)",
                "  1. msg_v1_aaaa  score 2.00",
                "truncated: max_items",
                "还有更多结果：复制下面这行追加 --cursor 即可翻页（cursor 约 15 分钟有效）",
                "  --cursor tok.abc",
            ]
        );
    }

    #[test]
    fn search_renders_hit_text_preview_when_present() {
        // human 渲染前由 CLI 附加 text 字段：命中带上正文预览时显示片段行。
        let data = json!({
            "hits": [{ "id": "msg_v1_aaaa", "score": 2.0, "text": "这是一条关于配置的正文" }],
            "generation": 3,
            "truncation": { "truncated": false, "reason": null },
        });
        let lines = render_success("search", Outcome::Success, &data, &Page::default());
        assert_eq!(
            lines,
            [
                "1 hit(s) (generation 3)",
                "  1. msg_v1_aaaa  score 2.00",
                "     这是一条关于配置的正文",
            ]
        );
    }

    #[test]
    fn search_renders_snippet_field_when_present() {
        // 旧字段名兼容：渲染器对 snippet/text 两者都认（ADR-0008 后摘要由
        // text 承载，snippet 回退读取）。
        let data = json!({
            "hits": [{ "id": "msg_v1_aaaa", "score": 2.0, "snippet": "新的 snippet 字段" }],
            "generation": 3,
            "truncation": { "truncated": false, "reason": null },
        });
        let lines = render_success("search", Outcome::Success, &data, &Page::default());
        assert_eq!(
            lines,
            [
                "1 hit(s) (generation 3)",
                "  1. msg_v1_aaaa  score 2.00",
                "     新的 snippet 字段",
            ]
        );
    }

    #[test]
    fn search_hit_without_preview_omits_snippet_line() {
        let data = json!({
            "hits": [{ "id": "msg_v1_aaaa", "score": 2.0 }],
            "generation": 3,
            "truncation": { "truncated": false, "reason": null },
        });
        let lines = render_success("search", Outcome::Success, &data, &Page::default());
        assert_eq!(
            lines,
            ["1 hit(s) (generation 3)", "  1. msg_v1_aaaa  score 2.00",]
        );
    }

    #[test]
    fn cursor_hint_requires_both_has_more_and_token() {
        let data = json!({
            "hits": [],
            "generation": 1,
            "truncation": { "truncated": false, "reason": null },
        });
        // has_more 但无令牌：宁缺续页行，也不渲染无法使用的提示。
        let page = Page {
            next_cursor: None,
            has_more: true,
        };
        assert_eq!(
            render_success("search", Outcome::Success, &data, &page),
            ["no hits", "提示：试试更短或更少的关键词（如只搜一个词）。",]
        );
        // 有令牌但 has_more=false：同样不给续页行。
        let page = Page {
            next_cursor: Some("tok".into()),
            has_more: false,
        };
        assert_eq!(
            render_success("search", Outcome::Success, &data, &page),
            ["no hits", "提示：试试更短或更少的关键词（如只搜一个词）。",]
        );
    }

    #[test]
    fn partial_outcome_without_truncation_metadata_degrades_to_placeholder() {
        let lines = render_success(
            "search",
            Outcome::Partial,
            &json!({ "hits": [] }),
            &Page::default(),
        );
        assert_eq!(
            lines,
            [
                "no hits",
                "提示：试试更短或更少的关键词（如只搜一个词）。",
                "truncated: ?"
            ]
        );
    }

    #[test]
    fn list_renders_id_and_sanitized_payload_preview() {
        let long_payload = format!("a\tb\nc{}", "d".repeat(100));
        let data = json!({
            "entries": [
                { "id": "msg_v1_aaaa", "payload": long_payload },
                { "id": "ses_v1_bbbb", "payload": "{\"document\":\"doc_v1_x\"}" },
            ],
            "generation": 4,
            "truncation": { "truncated": false, "reason": null },
        });
        let lines = render_success("list", Outcome::Success, &data, &Page::default());
        // 控制字符替换为空格后按 60 字符截断："a b c" 5 字符 + 55 个 d。
        let expected_preview = format!("a b c{}", "d".repeat(55));
        assert_eq!(expected_preview.chars().count(), LIST_PREVIEW_CHARS);
        assert_eq!(
            lines,
            [
                "2 entries (generation 4)".to_string(),
                format!("  msg_v1_aaaa  {expected_preview}"),
                "  ses_v1_bbbb  {\"document\":\"doc_v1_x\"}".to_string(),
            ]
        );
    }

    #[test]
    fn list_zero_entries_is_worded() {
        let data = json!({
            "entries": [],
            "generation": 0,
            "truncation": { "truncated": false, "reason": null },
        });
        let lines = render_success("list", Outcome::Success, &data, &Page::default());
        assert_eq!(lines, ["catalog is empty"]);
    }

    #[test]
    fn get_returns_payload_lines_verbatim_without_trailing_blanks() {
        let data = json!({ "payload": "alpha\nbeta\n\n" });
        let lines = render_success("get", Outcome::Success, &data, &Page::default());
        assert_eq!(lines, ["alpha", "beta"]);
    }

    #[test]
    fn get_null_payload_is_not_found() {
        let data = json!({ "payload": null });
        let lines = render_success("get", Outcome::Success, &data, &Page::default());
        assert_eq!(lines, ["not found"]);
    }

    #[test]
    fn show_renders_curated_fields_only() {
        // human 模式只展示 role/text/timestamp/session；内部字段留给 json 模式。
        let data = json!({
            "entity": {
                "text": "hello",
                "role": "user",
                "span": { "start": 10 },
                "is_sidechain": false,
                "timestamp": "2026-07-28T00:00:00Z",
                "session": "ses_v1_abc",
                "parent": null,
                "spans": [],
            }
        });
        let lines = render_success("show", Outcome::Success, &data, &Page::default());
        assert_eq!(
            lines,
            [
                "role: user",
                "timestamp: 2026-07-28T00:00:00Z",
                "session: ses_v1_abc",
                "text: hello",
                "用 context <session> 展开这个会话的完整上下文。",
            ]
        );
    }

    #[test]
    fn show_null_entity_is_not_found() {
        let data = json!({ "entity": null });
        let lines = render_success("show", Outcome::Success, &data, &Page::default());
        assert_eq!(lines, ["not found"]);
    }

    #[test]
    fn show_session_entity_falls_back_to_generic_kv() {
        // 会话容器没有 role/text：不套消息投影，按顶层字段展开；无 `?`、
        // 无编造的 context 提示。
        let data = json!({
            "entity": {
                "document": "doc_v1_x",
                "documents": ["doc_v1_x"],
                "messages": ["msg_v1_a", "msg_v1_b"],
            }
        });
        let lines = render_success("show", Outcome::Success, &data, &Page::default());
        assert_eq!(
            lines,
            [
                "document: doc_v1_x",
                "documents: [\"doc_v1_x\"]",
                "messages: [\"msg_v1_a\",\"msg_v1_b\"]",
            ]
        );
    }

    #[test]
    fn show_document_entity_falls_back_to_generic_kv() {
        let data = json!({
            "entity": {
                "provider": "claude-code",
                "variant": "claude-code/jsonl-v1",
                "fingerprint": "0123abcd",
                "len": 128,
            }
        });
        let lines = render_success("show", Outcome::Success, &data, &Page::default());
        assert_eq!(
            lines,
            [
                "fingerprint: 0123abcd",
                "len: 128",
                "provider: claude-code",
                "variant: claude-code/jsonl-v1",
            ]
        );
    }

    #[test]
    fn show_message_without_session_omits_fabricated_hint() {
        // 会话引用未知时 `context <session>` 提示无从执行：保留四行投影，
        // 不渲染提示行。
        let data = json!({
            "entity": {
                "role": "user",
                "text": "hello",
                "timestamp": "2026-07-28T00:00:00Z",
            }
        });
        let lines = render_success("show", Outcome::Success, &data, &Page::default());
        assert_eq!(
            lines,
            [
                "role: user",
                "timestamp: 2026-07-28T00:00:00Z",
                "session: ?",
                "text: hello",
            ]
        );
    }

    #[test]
    fn show_legacy_bare_text_payload_gets_curated_projection() {
        // main.rs 对非 JSON payload 的兜底形状 {role: null, text: <bytes>}：
        // 仍是消息实体，走 curated 投影而非 kv。
        let data = json!({ "entity": { "role": null, "text": "raw bytes" } });
        let lines = render_success("show", Outcome::Success, &data, &Page::default());
        assert_eq!(
            lines,
            ["role: ?", "timestamp: ?", "session: ?", "text: raw bytes",]
        );
    }

    #[test]
    fn context_renders_header_numbered_messages_and_evidence() {
        let data = json!({
            "session_id": "ses_v1_abc",
            "session": { "document": "doc_v1_x", "messages": ["msg_v1_a", "msg_v1_b"] },
            "branch_leaf": "msg_v1_b",
            "messages": [
                {
                    "id": "msg_v1_a",
                    "message_id": "msg_v1_a",
                    "payload": { "role": "user", "text": "hello\nworld", "is_sidechain": false },
                },
                {
                    "id": "msg_v1_b",
                    "message_id": "msg_v1_b",
                    "payload": { "role": "assistant", "text": "t".repeat(100) },
                },
                { "id": "msg_v1_c", "message_id": "msg_v1_c", "payload": { "role": null } },
            ],
            "evidence": [
                { "occurrence_id": "aa", "message_id": "msg_v1_a", "generation": 9 },
                { "occurrence_id": "bb", "message_id": "msg_v1_b", "generation": 9 },
            ],
            "truncation": { "truncated": true, "reason": "max_messages" },
            "generation": 9,
        });
        let lines = render_success("context", Outcome::Partial, &data, &Page::default());
        // msg_v1_b 的 100 个 t 超过 CONTEXT_TEXT_CHARS：截断并标注真实 wire id。
        let truncated_text = format!(
            "{}…(已截断,用 show msg_v1_b 看全文)",
            "t".repeat(CONTEXT_TEXT_CHARS)
        );
        assert_eq!(
            lines,
            [
                "session ses_v1_abc  branch leaf msg_v1_b  (generation 9)".to_string(),
                "  1. [user] hello world".to_string(),
                format!("  2. [assistant] {truncated_text}"),
                "  3. [?] ?".to_string(),
                "evidence: 2 span(s)".to_string(),
                "truncated: max_messages".to_string(),
            ]
        );
    }

    #[test]
    fn context_truncation_hint_falls_back_to_id_when_message_id_missing() {
        let data = json!({
            "session_id": "ses_v1_abc",
            "messages": [
                { "id": "msg_v1_only_id", "payload": { "role": "user", "text": "t".repeat(100) } },
            ],
            "evidence": [],
            "truncation": { "truncated": false, "reason": null },
            "generation": 1,
        });
        let lines = render_success("context", Outcome::Success, &data, &Page::default());
        assert_eq!(
            lines[1],
            format!(
                "  1. [user] {}…(已截断,用 show msg_v1_only_id 看全文)",
                "t".repeat(CONTEXT_TEXT_CHARS)
            )
        );
    }

    #[test]
    fn context_truncation_without_any_id_omits_show_hint() {
        let data = json!({
            "session_id": "ses_v1_abc",
            "messages": [
                { "payload": { "role": "user", "text": "t".repeat(100) } },
            ],
            "evidence": [],
            "truncation": { "truncated": false, "reason": null },
            "generation": 1,
        });
        let lines = render_success("context", Outcome::Success, &data, &Page::default());
        assert_eq!(
            lines[1],
            format!("  1. [user] {}…(已截断)", "t".repeat(CONTEXT_TEXT_CHARS))
        );
    }

    #[test]
    fn context_zero_messages_keeps_worded_header_and_evidence() {
        let data = json!({
            "session_id": "ses_v1_abc",
            "session": { "document": "doc_v1_x", "messages": [] },
            "branch_leaf": null,
            "messages": [],
            "evidence": [],
            "truncation": { "truncated": false, "reason": null },
            "generation": 2,
        });
        let lines = render_success("context", Outcome::Success, &data, &Page::default());
        assert_eq!(
            lines,
            [
                "session ses_v1_abc  branch leaf none  (generation 2)",
                "evidence: 0 span(s)",
            ]
        );
    }

    #[test]
    fn status_renders_entities_and_generation() {
        let data = json!({ "catalog_count": 5, "generation": 2 });
        let lines = render_success("status", Outcome::Success, &data, &Page::default());
        assert_eq!(lines, ["entities: 5", "generation: 2"]);
    }

    #[test]
    fn status_missing_fields_degrade_to_placeholders() {
        let lines = render_success("status", Outcome::Success, &json!({}), &Page::default());
        assert_eq!(lines, ["entities: ?", "generation: ?"]);
    }

    #[test]
    fn unknown_command_falls_back_to_sorted_key_value_lines() {
        let data = json!({
            "variant": "claude-code/v1",
            "committed": 3,
            "unchanged": 0,
            "skipped": 0,
            "generation": 4,
            "source_fp": "b3:abcd",
        });
        let lines = render_success("frobnicate", Outcome::Success, &data, &Page::default());
        assert_eq!(
            lines,
            [
                "committed: 3",
                "generation: 4",
                "skipped: 0",
                "source_fp: b3:abcd",
                "unchanged: 0",
                "variant: claude-code/v1",
            ]
        );
    }

    #[test]
    fn sync_renders_field_stats_with_unit_annotations() {
        let data = json!({
            "sources": 2,
            "messages": 10,
            "committed": 10,
            "emitted": 3,
            "unchanged": 7,
            "skipped": 0,
            "diagnostics": 0,
            "generation": 4,
        });
        let lines = render_success("sync", Outcome::Success, &data, &Page::default());
        assert_eq!(
            lines,
            [
                "sources: 2（本次扫描的源文件数）",
                "emitted: 3（本次新解析的消息条数）",
                "unchanged: 7（未变化的已有消息条数，不是文件数）",
                "skipped: 0（因格式无法入库的消息条数）",
                "generation: 4（当前入库代次）",
                "总结：新增 3 条消息。",
            ]
        );
        let data = json!({
            "tool": "agent-session-grep",
            "version": "0.1.0",
            "db": "not-checked",
            "schema": null,
        });
        let lines = render_success("doctor", Outcome::Success, &data, &Page::default());
        assert_eq!(
            lines,
            [
                "db: not-checked",
                "schema: null",
                "tool: agent-session-grep",
                "version: 0.1.0",
            ]
        );
    }

    #[test]
    fn ingest_renders_dedicated_single_source_fields() {
        // ingest 响应没有 `sources` 字段：专属版式恒报 1（单文件），只渲染
        // 响应实际携带的字段，无 `sources: ?`。
        let data = json!({
            "variant": "claude-code/jsonl-v1",
            "emitted": 3,
            "committed": 3,
            "unchanged": 0,
            "skipped": 0,
            "diagnostics": 1,
            "generation": 4,
            "source_fp": "b3:abcd",
        });
        let lines = render_success("ingest", Outcome::Success, &data, &Page::default());
        assert_eq!(
            lines,
            [
                "sources: 1（本次扫描的源文件数）",
                "variant: claude-code/jsonl-v1",
                "source_fp: b3:abcd",
                "committed: 3（本次新入库的消息条数）",
                "diagnostics: 1（解析诊断条数）",
                "总结：新增 3 条消息。",
            ]
        );
    }

    #[test]
    fn ingest_unchanged_file_summarizes_no_new_messages() {
        // 重复 ingest 未变化的文件：committed 为 0，结论行如实报"无变化"。
        let data = json!({
            "variant": "claude-code/jsonl-v1",
            "emitted": 3,
            "committed": 0,
            "unchanged": 3,
            "skipped": 0,
            "diagnostics": 0,
            "generation": 4,
            "source_fp": "b3:abcd",
        });
        let lines = render_success("ingest", Outcome::Success, &data, &Page::default());
        assert_eq!(
            lines,
            [
                "sources: 1（本次扫描的源文件数）",
                "variant: claude-code/jsonl-v1",
                "source_fp: b3:abcd",
                "committed: 0（本次新入库的消息条数）",
                "diagnostics: 0（解析诊断条数）",
                "总结：没有新增消息（源文件未变化）。",
            ]
        );
    }

    #[test]
    fn ingest_missing_fields_render_nothing_not_question_marks() {
        let lines = render_success("ingest", Outcome::Success, &json!({}), &Page::default());
        assert_eq!(lines, ["sources: 1（本次扫描的源文件数）"]);
    }

    #[test]
    fn non_object_data_never_panics_and_stays_single_line() {
        let odd_values = [
            json!(null),
            json!("x\r\ny"),
            json!(3),
            json!([1, 2]),
            json!({}),
        ];
        let commands = [
            "search", "list", "get", "show", "context", "status", "sync", "ingest", "wat",
        ];
        for command in commands {
            for data in &odd_values {
                for outcome in [Outcome::Success, Outcome::Partial] {
                    let lines = render_success(command, outcome, data, &page_more("tok"));
                    for line in &lines {
                        assert!(
                            !line.contains('\n') && !line.contains('\r'),
                            "control char leaked from {command}: {line:?}"
                        );
                    }
                    assert!(lines.last().is_none_or(|line| !line.trim().is_empty()));
                }
            }
        }
    }

    #[test]
    fn resume_table_renders_five_columns_in_contract_order() {
        let rows = [resume_row(
            "2026-08-14",
            "claude-code",
            Some("配置数据库连接"),
            Some("C:/dev/agent-session-grep"),
            "ses_v1_abc",
        )];
        let output = render_session_resume_table(&rows);
        // 列宽：日期 10、Provider 11（内容全宽）、Session ID 10；
        // 剩余 100 - 10 - 11 - 10 - 12 = 57 → 标题 19、工作目录 37。
        let header = format!(
            "日期{} | Provider{} | 会话标题{} | 工作目录{} | Session ID",
            " ".repeat(6),
            " ".repeat(3),
            " ".repeat(11),
            " ".repeat(29),
        );
        let body = format!(
            "2026-08-14 | claude-code | 配置数据库连接{} | C:/dev/agent-session-grep{} | ses_v1_abc",
            " ".repeat(5),
            " ".repeat(12),
        );
        assert_eq!(output, format!("{header}\n{body}"));
    }

    #[test]
    fn resume_table_never_truncates_provider_or_session_id() {
        let provider = "hyperbolic-parallel-provider-v9";
        let session_id = format!("ses_v1_{}", "abcdef0123456789".repeat(4));
        let rows = [resume_row(
            "2026-08-14",
            provider,
            Some("短标题"),
            Some("C:/a"),
            &session_id,
        )];
        let output = render_session_resume_table(&rows);
        let body = output.lines().nth(1).unwrap();
        // Session ID 是末列且不加填充：整行必须以完整 ID 收尾。
        assert!(
            body.ends_with(&session_id),
            "session id truncated: {body:?}"
        );
        // Provider 按内容全宽：完整出现且紧跟列分隔符。
        assert!(
            body.contains(&format!("{provider} |")),
            "provider truncated: {body:?}"
        );
    }

    #[test]
    fn resume_table_renders_dash_for_missing_values() {
        let rows = [
            resume_row("", "codex", None, None, "ses_v1_xyz"),
            resume_row("", "", None, None, "ses_v1_uvw"),
        ];
        let output = render_session_resume_table(&rows);
        // 列宽：日期 10、Provider 8、Session ID 10；剩余 60 → 标题 21、工作目录 39。
        let row1 = format!(
            "—{} | codex{} | —{} | —{} | ses_v1_xyz",
            " ".repeat(9),
            " ".repeat(3),
            " ".repeat(20),
            " ".repeat(38),
        );
        let row2 = format!(
            "—{} | —{} | —{} | —{} | ses_v1_uvw",
            " ".repeat(9),
            " ".repeat(7),
            " ".repeat(20),
            " ".repeat(38),
        );
        assert_eq!(output.lines().nth(1), Some(row1.as_str()));
        assert_eq!(output.lines().nth(2), Some(row2.as_str()));
    }

    #[test]
    fn collapse_middle_keeps_head_and_tail_segments() {
        // 30 列预算：首段 C:/Users、尾段 agent-session-grep，中间折叠。
        assert_eq!(
            collapse_middle("C:/Users/someone/dev/agent-session-grep", 30),
            "C:/Users/…/agent-session-grep"
        );
        // 反斜杠路径同样折叠，分隔符保持原样。
        assert_eq!(
            collapse_middle(r"C:\Users\someone\dev\agent-session-grep", 30),
            r"C:\Users\…\agent-session-grep"
        );
        // 宽度足够时原样返回。
        assert_eq!(
            collapse_middle("C:/dev/agent-session-grep", 40),
            "C:/dev/agent-session-grep"
        );
        // 单段路径退化为字符级中间折叠。
        assert_eq!(
            collapse_middle("abcdefghijklmnopqrstuvwxyz", 10),
            "abcd…vwxyz"
        );
    }

    #[test]
    fn display_width_counts_cjk_as_two_columns() {
        assert_eq!(display_width("会话标题"), 8);
        assert_eq!(display_width("abc"), 3);
        assert_eq!(display_width("2026-08-14"), 10);
        // 12 列预算：按显示宽度截前缀（10 列）再补 `…`（1 列）。
        assert_eq!(
            truncate_tail_ellipsis("这是一段非常非常长的会话标题", 12),
            "这是一段非…"
        );
        // 未超宽不截断。
        assert_eq!(truncate_tail_ellipsis("short", 12), "short");
    }

    #[test]
    fn resume_table_truncates_cjk_title_by_display_width() {
        // 标题列 19：20 个 CJK 字（40 列）→ 按显示宽度保留 9 字 + `…`。
        let rows = [resume_row(
            "2026-08-14",
            "claude-code",
            Some(&"标".repeat(20)),
            Some("C:/a"),
            "ses_v1_abc",
        )];
        let output = render_session_resume_table(&rows);
        let body = output.lines().nth(1).unwrap();
        let expected_title = format!("{}…", "标".repeat(9));
        assert!(
            body.contains(&format!("{expected_title} |")),
            "title not truncated by display width: {body:?}"
        );
    }

    #[test]
    fn resume_table_sanitizes_newlines_and_tabs() {
        let rows = [resume_row(
            "2026-08-14",
            "claude-code",
            Some("第一行\n第二行\ttab"),
            Some("C:/a\r\nb"),
            "ses_v1_abc",
        )];
        let output = render_session_resume_table(&rows);
        assert!(!output.contains('\t'));
        assert!(!output.contains('\r'));
        assert!(!output.ends_with('\n'));
        let body = output.lines().nth(1).unwrap();
        assert!(
            body.contains("第一行 第二行 tab"),
            "control chars not cleaned: {body:?}"
        );
        assert!(
            body.contains("C:/a  b"),
            "cwd control chars not cleaned: {body:?}"
        );
    }

    #[test]
    fn resume_table_empty_input_renders_empty_string() {
        assert_eq!(render_session_resume_table(&[]), "");
    }

    fn resume_row(
        date: &str,
        provider: &str,
        title: Option<&str>,
        cwd: Option<&str>,
        session: &str,
    ) -> SessionResumeTableRow {
        SessionResumeTableRow {
            date_ymd: date.to_string(),
            provider: provider.to_string(),
            title: title.map(str::to_string),
            working_directory: cwd.map(str::to_string),
            session_id: session.to_string(),
        }
    }
}
