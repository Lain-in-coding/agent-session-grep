//! TUI Preview：交互式只读浏览。
//!
//! 本文件是薄 glue：终端生命周期（raw mode + 备用屏 + panic 恢复钩子）、
//! crossterm 事件 → [`KeyInput`] 映射、[`Effect`] 对 App ADT 的同步执行、
//! ratatui 组件按 view-model 字符串装配。全部状态转移与渲染决策在纯核心
//! core.rs（可无终端单测）；本层不含业务规则——分页令牌、分支策略、
//! 命中→会话解析全部经 [`AppRequest`] 交给 Application。
//!
//! 约束：
//! - 非交互 stdout 直接 usage error（exit 2），不碰 raw mode（design §0.4）。
//! - init 后的终端 I/O 失败 → 恢复终端后返回 `source_io`（exit 5）。
//! - App 错误经 [`ProtocolError`] 映射为状态行文本，UI 继续运行、绝不崩。
//! - 只处理 `KeyEventKind::Press`（Windows 会同时上报 Release，不滤则按键双发）。

mod core;

use crate::protocol::{CanonicalCode, Outcome, ProtocolError};
use crate::tui::core::{
    ContextMessage, ContextView, Effect, KeyInput, Model, Msg, ResumeMetadataView, Screen,
    SearchHitView, SearchPage,
};
use crate::tui::core::{context_lines, hit_lines, resume_lines, status_line, title_line, update};
use crate::{CliError, render, store_ref};
use agent_session_grep_adapters_sqlite::SqliteStore;
use agent_session_grep_application::{
    App, AppError, AppRequest, AppResponse, ContextLevel, ResponseBudget,
};
use agent_session_grep_domain::{ContextPolicy, StableId};
use agent_session_grep_ports::{ResumeClaimsStore, SearchFilters};
use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use ratatui::Frame;
use ratatui::layout::{Constraint, Layout};
use ratatui::style::{Modifier, Style};
use ratatui::widgets::{List, ListItem, ListState, Paragraph};
use std::collections::HashMap;
use std::io::IsTerminal;
use std::time::Duration;

/// 检索页大小：与 main.rs `search` 无 `--max-items` 时的保守默认一致。
const SEARCH_PAGE_LIMIT: usize = 20;

/// 在已打开的只读 store 上运行交互式 TUI，直到用户退出。
///
/// 终端恢复覆盖全部路径：正常退出与错误路径由本函数显式 restore，
/// panic 路径由 `ratatui::try_init` 安装的 panic hook 兜底。
pub(crate) fn run(store: &SqliteStore) -> Result<Outcome, CliError> {
    if !std::io::stdout().is_terminal() {
        return Err(CliError::usage("tui requires an interactive terminal"));
    }
    let mut terminal = ratatui::try_init().map_err(|error| {
        // try_init 内部先 enable_raw_mode 再 EnterAlternateScreen：若第二步
        // 失败，raw mode 已经开启。此时必须主动 restore，否则终端残留 raw
        // mode（无回显、无行缓冲）。ratatui::restore 是幂等的，失败路径安全。
        ratatui::restore();
        ProtocolError::new(
            CanonicalCode::SourceIo,
            format!("cannot initialize terminal: {error}"),
        )
    })?;
    let result = event_loop(&mut terminal, store);
    ratatui::restore();
    result?;
    Ok(Outcome::Success)
}

/// Headless structural projection for the release consistency harness.
///
/// This does not automate a terminal. It drives the same [`Effect::Search`]
/// path as the interactive reducer (shared Application projection) and
/// serializes only the stable fields used by the cross-entry-point
/// comparison: `outcome`, `data.hits[].id`, `page.has_more`, `page.next_cursor`.
pub(crate) fn snapshot_search(
    store: &SqliteStore,
    query: String,
) -> Result<serde_json::Value, CliError> {
    match execute(
        store,
        Effect::Search {
            query,
            cursor: None,
            facets: agent_session_grep_ports::SearchFacets::default(),
        },
    ) {
        Msg::SearchLoaded(page) => {
            let outcome = if page.truncated { "partial" } else { "success" };
            Ok(serde_json::json!({
                "outcome": outcome,
                "data": {
                    "hits": page.hits.into_iter().map(|hit| serde_json::json!({
                        "id": hit.id,
                    })).collect::<Vec<_>>(),
                },
                "page": {
                    "has_more": page.has_more,
                    "next_cursor": page.next_cursor,
                },
                "warnings": [],
            }))
        }
        Msg::EffectFailed(message) => Err(CliError::usage(format!(
            "tui snapshot search failed: {message}"
        ))),
        _ => Err(CliError::usage(
            "tui snapshot search received an unexpected projection",
        )),
    }
}

/// 主循环：draw → poll(250ms) → 按键映射 → update → 内联执行 Effect 并回灌。
fn event_loop(
    terminal: &mut ratatui::DefaultTerminal,
    store: &SqliteStore,
) -> Result<(), CliError> {
    let mut model = Model::default();
    loop {
        if let Err(error) = terminal.draw(|frame| draw(frame, &model)) {
            return Err(term_io(error));
        }
        if !event::poll(Duration::from_millis(250)).map_err(term_io)? {
            continue;
        }
        let Some(key) = key_input(event::read().map_err(term_io)?) else {
            continue;
        };
        let (next, mut effect) = update(model, Msg::Key(key));
        model = next;
        // 同步 Effect（design §0.3）：查询在 UI 线程内联执行，结果 Msg 回灌 reducer。
        while let Some(pending) = effect.take() {
            let msg = execute(store, pending);
            let (next, follow) = update(model, msg);
            model = next;
            effect = follow;
        }
        if model.quit {
            return Ok(());
        }
    }
}

/// crossterm 事件 → 纯核心 [`KeyInput`]。仅 Press 有效；
/// Ctrl 组合只识别 Ctrl+C，其余丢弃（不把控制字符打进输入框）。
fn key_input(event: Event) -> Option<KeyInput> {
    let Event::Key(key) = event else {
        return None;
    };
    if key.kind != KeyEventKind::Press {
        return None;
    }
    if key.modifiers.contains(KeyModifiers::CONTROL) {
        return match key.code {
            KeyCode::Char('c') | KeyCode::Char('C') => Some(KeyInput::CtrlC),
            _ => None,
        };
    }
    match key.code {
        // 控制字符不是文本：某些终端把 DEL/ESC 之类当 `Char` 上报，打进输入框
        // 后会随查询串一起渲染进终端（见 core.rs `fold_controls`）。这里就地丢弃，
        // 与上面 Ctrl 组合的处理同一条规则。
        KeyCode::Char(c) if c.is_control() => None,
        KeyCode::Char(c) => Some(KeyInput::Char(c)),
        KeyCode::Enter => Some(KeyInput::Enter),
        KeyCode::Esc => Some(KeyInput::Esc),
        KeyCode::Up => Some(KeyInput::Up),
        KeyCode::Down => Some(KeyInput::Down),
        KeyCode::PageUp => Some(KeyInput::PgUp),
        KeyCode::PageDown => Some(KeyInput::PgDn),
        KeyCode::Backspace => Some(KeyInput::Backspace),
        _ => None,
    }
}

/// 执行一个 Effect：构造 [`AppRequest`]（与 main.rs dispatch 同参），把
/// [`AppResponse`] 投影为平数据 Msg。失败进状态行，绝不向上抛、绝不 panic。
fn execute(store: &SqliteStore, effect: Effect) -> Msg {
    let app = App::with_resume(store_ref(store), store_ref(store), store_ref(store));
    match effect {
        Effect::Search {
            query,
            cursor,
            facets,
        } => {
            let request = AppRequest::Search {
                query,
                filters: SearchFilters::default(),
                limit: SEARCH_PAGE_LIMIT,
                cursor,
                budget: ResponseBudget::default(),
                // Facets come from the pure-core Model toggles (m/k keys).
                facets,
                include_system: false,
                group_by_session: false,
                mode: agent_session_grep_ports::RetrievalMode::Lexical,
                query_embedding: None,
            };
            match app.handle(request) {
                Ok(response) => search_msg(response),
                Err(error) => failed(error),
            }
        }
        Effect::ResolveAndLoadContext { hit_id, policy } => resolve_and_load(&app, &hit_id, policy),
        Effect::LoadContext { session_id, policy } => load_context(&app, &session_id, policy),
        Effect::LoadResumeMetadata { session_id } => load_resume_metadata(&app, &session_id),
    }
}

/// `AppResponse::Search` → 平数据页投影；`has_more` 与 envelope 同源（令牌在场即有下一页）。
fn search_msg(response: AppResponse) -> Msg {
    match response {
        AppResponse::Search {
            hits,
            next_cursor,
            generation,
            truncation,
            retrieval_mode: _,
            fallback_warning: _,
        } => {
            let hits = hits
                .into_iter()
                .map(|hit| SearchHitView {
                    id: hit.id.as_str().to_string(),
                    score: hit.score,
                    session_id: hit.session_id,
                    resume_available: hit.resume_available,
                    // Application 已按 ADR-0008 装配好摘要；这里只透传。
                    snippet: hit.text.unwrap_or_default(),
                })
                .collect();
            Msg::SearchLoaded(SearchPage {
                hits,
                has_more: next_cursor.is_some(),
                next_cursor,
                generation,
                truncated: truncation.truncated,
                truncation_reason: truncation.reason,
            })
        }
        _ => internal("unexpected response for search"),
    }
}

/// 命中→会话解析：Application 按 distinct Session 返回 placement candidates。
/// 零候选如实报 index-only；多个 Session 明确报歧义，绝不选择兼容 alias。
fn resolve_and_load<R: ResumeClaimsStore>(
    app: &App<&SqliteStore, &SqliteStore, R>,
    hit_id: &str,
    policy: ContextPolicy,
) -> Msg {
    let Some(id) = StableId::from_wire(hit_id) else {
        return Msg::EffectFailed(format!(
            "error [invalid_request]: not a valid entity id: {hit_id}"
        ));
    };
    let candidates = match app.handle(AppRequest::MessageContexts { message_id: id }) {
        Ok(AppResponse::MessageContexts { candidates, .. }) => candidates,
        Ok(_) => return internal("unexpected response for message contexts"),
        Err(error) => return failed(error),
    };
    match candidates.as_slice() {
        [] => Msg::EffectFailed("hit has no session (index-only row)".to_string()),
        [candidate] => load_context(app, &candidate.session_id, policy),
        _ => Msg::EffectFailed(format!(
            "hit belongs to {} sessions; choose an explicit session",
            candidates.len()
        )),
    }
}

/// 装配会话上下文并投影为 [`ContextView`]。
///
/// 投影复用 CLI 的 [`render`]：截断/警告（含 unknown-precision 降级计数）与
/// Human/Robot/MCP 三面完全同源，本层不重算任何呈现规则。
fn load_context<R: ResumeClaimsStore>(
    app: &App<&SqliteStore, &SqliteStore, R>,
    session_wire: &str,
    policy: ContextPolicy,
) -> Msg {
    let Some(session_id) = StableId::from_wire(session_wire) else {
        return Msg::EffectFailed(format!(
            "error [invalid_request]: not a valid session id: {session_wire}"
        ));
    };
    let request = AppRequest::Context {
        session_id,
        policy,
        level: ContextLevel::Raw,
        budget: ResponseBudget::default(),
    };
    let response = match app.handle(request) {
        Ok(response @ AppResponse::Context { .. }) => response,
        Ok(_) => return internal("unexpected response for context"),
        Err(error) => return failed(error),
    };
    let (_, data, _, warnings) = render(response);
    Msg::ContextLoaded(context_view(&data, warnings))
}

/// 通过 Application 固定契约读取 Resume Metadata；只投影结构化字段，
/// 不读取 Source/transcript path，也不构造或执行恢复命令。
fn load_resume_metadata<R: ResumeClaimsStore>(
    app: &App<&SqliteStore, &SqliteStore, R>,
    session_wire: &str,
) -> Msg {
    let Some(session_id) = StableId::from_wire(session_wire) else {
        return Msg::EffectFailed(format!(
            "error [invalid_request]: not a valid session id: {session_wire}"
        ));
    };
    match app.handle(AppRequest::GetSessionResume { session_id }) {
        Ok(AppResponse::SessionResume(metadata)) => Msg::ResumeLoaded(ResumeMetadataView {
            session_id: metadata.session_id.as_str().to_string(),
            provider_id: metadata.provider_id,
            resume_available: metadata.resume_available,
            provider_session_id: metadata.provider_session_id,
            original_working_directory: metadata.original_working_directory,
            unavailable_reason: metadata.unavailable_reason,
        }),
        Ok(_) => internal("unexpected response for session resume"),
        Err(error) => failed(error),
    }
}

/// 从 [`render`] 的 context data JSON 建 [`ContextView`]。
/// 证据按 authoritative placement/occurrence id 对齐；重复 Message 不折叠。
fn context_view(data: &serde_json::Value, warnings: Vec<String>) -> ContextView {
    let empty = Vec::new();
    let spans = data["evidence"].as_array().unwrap_or(&empty);
    let precision_of: HashMap<&str, &str> = spans
        .iter()
        .filter_map(|span| Some((span["occurrence_id"].as_str()?, span["precision"].as_str()?)))
        .collect();
    let messages = data["messages"].as_array().unwrap_or(&empty);
    let lines = messages
        .iter()
        .map(|message| {
            let placement_id = message["placement_id"].as_str().unwrap_or("");
            let precision = precision_of.get(placement_id).copied().unwrap_or("unknown");
            context_message(precision, &message["payload"])
        })
        .collect();
    ContextView {
        session_id: data["session_id"].as_str().unwrap_or("").to_string(),
        lines,
        truncated: data["truncation"]["truncated"].as_bool().unwrap_or(false),
        truncation_reason: data["truncation"]["reason"].as_str().map(str::to_string),
        warnings,
        generation: data["generation"].as_u64().unwrap_or(0),
    }
}

/// 单条消息的展示投影：role/text 缺失如实降级（`?` 占位 / 空串），精度由调用方对齐传入。
fn context_message(precision: &str, payload: &serde_json::Value) -> ContextMessage {
    ContextMessage {
        role: payload["role"].as_str().unwrap_or("?").to_string(),
        text: payload["text"].as_str().unwrap_or("").to_string(),
        precision: precision.to_string(),
    }
}

/// App 错误 → 状态行文本：同一 canonical 映射（`error [<code>]: <msg>`），UI 不退出。
fn failed(error: AppError) -> Msg {
    let protocol_error = ProtocolError::from(error);
    Msg::EffectFailed(format!(
        "error [{}]: {}",
        protocol_error.code.as_str(),
        protocol_error.message
    ))
}

/// 响应形状与请求不符——App 契约被破坏的 bug 信号，按 internal 上报状态行。
fn internal(message: &str) -> Msg {
    Msg::EffectFailed(format!("error [internal]: {message}"))
}

/// init 之后的终端 I/O 失败：归 `source_io`（exit 5）；恢复由 run 的收尾保证。
fn term_io(error: std::io::Error) -> CliError {
    let message = format!("terminal io error: {error}");
    ProtocolError::new(CanonicalCode::SourceIo, message).into()
}

/// 绘制：内容全部来自 view-model 字符串；样式仅限选中行前缀与反色状态栏。
fn draw(frame: &mut Frame, model: &Model) {
    let title = Paragraph::new(title_line(model));
    let status =
        Paragraph::new(status_line(model)).style(Style::new().add_modifier(Modifier::REVERSED));
    match model.screen {
        Screen::Search | Screen::Results => {
            let [title_area, input_area, list_area, status_area] = Layout::vertical([
                Constraint::Length(1),
                Constraint::Length(1),
                Constraint::Min(0),
                Constraint::Length(1),
            ])
            .areas(frame.area());
            frame.render_widget(title, title_area);
            let input = Paragraph::new(format!("query> {}", model.input));
            frame.render_widget(input, input_area);
            let items: Vec<ListItem> = hit_lines(model).into_iter().map(ListItem::new).collect();
            // 结果列表是 stateful 渲染：每帧构造 ListState 并 select 当前行，
            // ratatui 会把选中行滚入可视区（翻页/下移后不再滚出屏幕）。
            // 选中行前缀由 hit_lines 的 `> ` 提供，这里不再设 highlight_symbol。
            let mut list_state = ListState::default();
            if model.selected < items.len() {
                list_state.select(Some(model.selected));
            }
            let list = List::new(items);
            frame.render_stateful_widget(list, list_area, &mut list_state);
            frame.render_widget(status, status_area);
        }
        Screen::Context => {
            let [title_area, resume_area, body_area, status_area] = Layout::vertical([
                Constraint::Length(1),
                Constraint::Length(5),
                Constraint::Min(0),
                Constraint::Length(1),
            ])
            .areas(frame.area());
            frame.render_widget(title, title_area);
            let resume = Paragraph::new(resume_lines(model).join("\n"));
            frame.render_widget(resume, resume_area);
            let body = context_lines(model).join("\n");
            // ratatui 的 Paragraph 内部算 `area.height + scroll`（u16 加法）：
            // 把越界滚动饱和到 u16::MAX 会让它在 debug build 里溢出 panic。
            // 按可视高度留出余量后再夹取，越界滚动退化为"停在最底"。
            let ceiling = u16::MAX - body_area.height;
            let scroll = u16::try_from(model.scroll).unwrap_or(ceiling).min(ceiling);
            let paragraph = Paragraph::new(body).scroll((scroll, 0));
            frame.render_widget(paragraph, body_area);
            frame.render_widget(status, status_area);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_session_grep_adapters_sqlite::SourceBatch;
    use agent_session_grep_domain::{IdKind, MessagePlacement, Stability};
    use serde_json::json;

    fn id(kind: IdKind, tag: &str) -> StableId {
        StableId::derive(kind, Stability::Reconstructed, &[tag.as_bytes()])
    }

    #[test]
    fn search_msg_projects_resume_availability_without_source_data() {
        let response = AppResponse::Search {
            hits: vec![agent_session_grep_ports::SearchHit {
                id: id(IdKind::Message, "tui-resume-hit"),
                score: 2.0,
                session_id: Some(
                    id(IdKind::Session, "tui-resume-session")
                        .as_str()
                        .to_string(),
                ),
                text: Some("preview".to_string()),
                why_matched: Vec::new(),
                suggested_next_commands: Vec::new(),
                occurrences: 1,
                resume_available: true,
            }],
            next_cursor: None,
            generation: 7,
            truncation: agent_session_grep_application::Truncation {
                truncated: false,
                reason: None,
            },
            retrieval_mode: agent_session_grep_ports::RetrievalMode::Lexical,
            fallback_warning: None,
        };

        let Msg::SearchLoaded(page) = search_msg(response) else {
            panic!("expected SearchLoaded");
        };

        assert_eq!(page.hits.len(), 1);
        assert!(page.hits[0].resume_available);
        assert!(page.hits[0].session_id.is_some());
        // Application 装配的摘要必须到达列表投影，否则 Results 屏只剩 UUID+score。
        assert_eq!(page.hits[0].snippet, "preview");
    }

    #[test]
    fn load_resume_metadata_uses_application_fixed_shape() {
        let store = SqliteStore::open_in_memory().unwrap();
        let app = App::new(store_ref(&store), store_ref(&store));
        let session = id(IdKind::Session, "tui-resume-detail");

        let result = load_resume_metadata(&app, session.as_str());

        let Msg::ResumeLoaded(metadata) = result else {
            panic!("expected ResumeLoaded");
        };
        assert_eq!(metadata.session_id, session.as_str());
        assert!(!metadata.resume_available);
        assert!(metadata.provider_id.is_none());
        assert!(metadata.provider_session_id.is_none());
        assert!(metadata.original_working_directory.is_none());
        assert!(metadata.unavailable_reason.is_some());
    }

    fn source_batch(
        source_path: &str,
        session: StableId,
        document: StableId,
        message: StableId,
        ordinals: &[u32],
    ) -> SourceBatch {
        let message_payload = json!({
            "role": "assistant",
            "text": "shared TUI message",
            "timestamp": "2026-07-28T03:00:00Z",
        })
        .to_string()
        .into_bytes();
        let session_payload = json!({
            "document": document.as_str(),
            "documents": [document.as_str()],
            "messages": [message.as_str()],
        })
        .to_string()
        .into_bytes();
        let document_payload = json!({
            "provider": "synthetic",
            "variant": "synthetic/jsonl-v1",
            "fingerprint": format!("fingerprint-{source_path}"),
            "len": 32,
        })
        .to_string()
        .into_bytes();
        let placements = ordinals
            .iter()
            .map(|ordinal| {
                MessagePlacement::new(
                    session.clone(),
                    document.clone(),
                    message.clone(),
                    *ordinal,
                    false,
                    None,
                )
            })
            .collect();
        SourceBatch {
            source_path: source_path.to_string(),
            entries: vec![
                (message, message_payload, "shared TUI message".to_string()),
                (session, session_payload, String::new()),
                (document, document_payload, String::new()),
            ],
            placements,
            edges: Vec::new(),
            activities: Vec::new(),
            usage_events: Vec::new(),
            relation_complete: true,
            len_bytes: None,
            fingerprint: None,
            provider_id: None,
            resume_claims: Vec::new(),
        }
    }

    #[test]
    fn resolve_and_load_treats_multiple_placements_in_one_session_as_one_candidate() {
        let store = SqliteStore::open_in_memory().unwrap();
        let message = id(IdKind::Message, "tui-shared-message");
        let source = source_batch(
            "tui-one-session",
            id(IdKind::Session, "tui-session"),
            id(IdKind::Document, "tui-document"),
            message.clone(),
            &[0, 1],
        );
        store
            .commit_source_batches_if_changed(std::slice::from_ref(&source))
            .unwrap();
        let app = App::new(store_ref(&store), store_ref(&store));

        let result = resolve_and_load(&app, message.as_str(), ContextPolicy::Mainline);
        assert!(
            matches!(result, Msg::ContextLoaded(view) if view.lines.len() == 1),
            "multiple placements in one Session must not look ambiguous"
        );
    }

    #[test]
    fn resolve_and_load_reports_ambiguity_only_for_distinct_sessions() {
        let store = SqliteStore::open_in_memory().unwrap();
        let message = id(IdKind::Message, "tui-ambiguous-message");
        let sources = [
            source_batch(
                "tui-session-a-source",
                id(IdKind::Session, "tui-session-a"),
                id(IdKind::Document, "tui-document-a"),
                message.clone(),
                &[0],
            ),
            source_batch(
                "tui-session-b-source",
                id(IdKind::Session, "tui-session-b"),
                id(IdKind::Document, "tui-document-b"),
                message.clone(),
                &[0],
            ),
        ];
        store.commit_source_batches_if_changed(&sources).unwrap();
        let app = App::new(store_ref(&store), store_ref(&store));

        let result = resolve_and_load(&app, message.as_str(), ContextPolicy::Mainline);
        assert!(
            matches!(result, Msg::EffectFailed(message) if message.contains("2 sessions")),
            "distinct Sessions must remain explicitly ambiguous"
        );
    }

    /// Render `draw` through ratatui's `TestBackend` and hand back the cell
    /// buffer. This is the only way to exercise the real layout/widget math
    /// without a terminal — the reducer tests cannot catch a panic that lives
    /// in the render half.
    fn rendered(model: &Model, width: u16, height: u16) -> ratatui::buffer::Buffer {
        let backend = ratatui::backend::TestBackend::new(width, height);
        let mut terminal = ratatui::Terminal::new(backend).expect("test terminal");
        terminal
            .draw(|frame| draw(frame, model))
            .expect("draw must not fail");
        terminal.backend().buffer().clone()
    }

    /// Hostile-but-real content: CJK/emoji (unicode width != byte length), an
    /// ANSI escape sequence and raw control bytes (transcripts carry shell
    /// output verbatim — `msg_v1_2cf77e63-…` in the local catalog starts with
    /// `\x1b[31;1m   Compiling krates v0.21.2\x1b[0m`), a very long single
    /// line, and empty strings.
    fn hostile_model(screen: Screen) -> Model {
        let nasty = "\u{1b}[31m红色\u{7}\r\tCJK 中文 emoji 👨‍👩‍👧‍👦 \u{0}end";
        Model {
            screen,
            // 输入框只可能拿到 key_input 放行的可打印字符（见
            // `key_input_rejects_control_characters`），所以这里放宽字符而非控制符。
            input: "中文 emoji 👨‍👩‍👧‍👦 query".to_string(),
            query: nasty.to_string(),
            hits: vec![
                SearchHitView {
                    id: nasty.to_string(),
                    score: f32::NAN,
                    session_id: Some("中文会话\u{1b}[0m".to_string()),
                    resume_available: true,
                    snippet: format!("{nasty} {}", "x".repeat(10_000)),
                },
                SearchHitView {
                    id: String::new(),
                    score: 0.0,
                    session_id: None,
                    resume_available: false,
                    snippet: String::new(),
                },
            ],
            selected: 1,
            context: Some(ContextView {
                session_id: nasty.to_string(),
                lines: vec![
                    ContextMessage {
                        role: nasty.to_string(),
                        text: "x".repeat(10_000),
                        precision: String::new(),
                    },
                    ContextMessage {
                        role: String::new(),
                        text: String::new(),
                        precision: nasty.to_string(),
                    },
                ],
                truncated: true,
                truncation_reason: Some(nasty.to_string()),
                warnings: vec![nasty.to_string()],
                generation: u64::MAX,
            }),
            resume: Some(ResumeMetadataView {
                session_id: nasty.to_string(),
                provider_id: Some(nasty.to_string()),
                resume_available: true,
                provider_session_id: Some(String::new()),
                original_working_directory: Some("C:/中文/路径 👩‍💻".to_string()),
                unavailable_reason: None,
            }),
            scroll: 1,
            status: Some(nasty.to_string()),
            warnings: vec![nasty.to_string()],
            ..Model::default()
        }
    }

    #[test]
    fn draw_survives_hostile_content_at_degenerate_terminal_sizes() {
        for screen in [Screen::Search, Screen::Results, Screen::Context] {
            let model = hostile_model(screen);
            // 1x1 / 10x3 / 3-row are the sizes where the fixed-Length rows
            // (title + input/resume + status) do not fit at all.
            for (width, height) in [(1, 1), (10, 3), (3, 40), (80, 24), (200, 2)] {
                let buffer = rendered(&model, width, height);
                for (index, cell) in buffer.content.iter().enumerate() {
                    assert!(
                        !cell.symbol().chars().any(char::is_control),
                        "control character {:?} at cell {index} ({width}x{height}, {screen:?})",
                        cell.symbol()
                    );
                }
            }
        }
    }

    #[test]
    fn draw_clamps_out_of_range_scroll() {
        // ratatui 的 Paragraph 内部算 `area.height + scroll`（u16 加法）：把越界
        // 滚动饱和到 u16::MAX 会在 debug build 里溢出 panic，而不是停在最底行。
        let model = Model {
            screen: Screen::Context,
            context: Some(ContextView {
                session_id: "ses_v1_scroll".to_string(),
                lines: vec![ContextMessage {
                    role: "user".to_string(),
                    text: "only line".to_string(),
                    precision: "byte".to_string(),
                }],
                truncated: false,
                truncation_reason: None,
                warnings: Vec::new(),
                generation: 1,
            }),
            scroll: usize::MAX,
            ..Model::default()
        };

        rendered(&model, 40, 12);
        rendered(&model, 1, 1);
    }

    #[test]
    fn key_input_rejects_control_characters() {
        let press = |code: KeyCode| {
            key_input(Event::Key(crossterm::event::KeyEvent::new(
                code,
                KeyModifiers::NONE,
            )))
        };
        for control in ['\u{1b}', '\u{7f}', '\u{0}', '\r', '\n', '\t'] {
            assert_eq!(
                press(KeyCode::Char(control)),
                None,
                "control char {control:?} must not reach the input box"
            );
        }
        assert_eq!(press(KeyCode::Char('中')), Some(KeyInput::Char('中')));
        assert_eq!(press(KeyCode::Enter), Some(KeyInput::Enter));
    }

    #[test]
    fn draw_renders_empty_model_without_panicking() {
        for screen in [Screen::Search, Screen::Results, Screen::Context] {
            let model = Model {
                screen,
                ..Model::default()
            };
            rendered(&model, 80, 24);
            rendered(&model, 1, 1);
        }
    }

    #[test]
    fn context_view_aligns_evidence_by_placement_id_not_message_or_position() {
        let data = json!({
            "session_id": "ses_v1_tui",
            "messages": [
                {
                    "id": "msg_v1_shared",
                    "message_id": "msg_v1_shared",
                    "placement_id": "plc_v1_first",
                    "payload": {"role": "assistant", "text": "first"},
                },
                {
                    "id": "msg_v1_shared",
                    "message_id": "msg_v1_shared",
                    "placement_id": "plc_v1_second",
                    "payload": {"role": "assistant", "text": "second"},
                },
            ],
            "evidence": [
                {"occurrence_id": "plc_v1_second", "precision": "byte"},
                {"occurrence_id": "plc_v1_first", "precision": "unknown"},
            ],
            "truncation": {"truncated": false, "reason": null},
            "generation": 7,
        });

        let view = context_view(&data, Vec::new());
        assert_eq!(view.lines.len(), 2);
        assert_eq!(view.lines[0].text, "first");
        assert_eq!(view.lines[0].precision, "unknown");
        assert_eq!(view.lines[1].text, "second");
        assert_eq!(view.lines[1].precision, "byte");
    }
}
