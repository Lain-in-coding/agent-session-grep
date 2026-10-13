//! TUI 纯核心（Elm-style，design §2）：
//! `Model` + `Msg` + `Effect` + [`update`] reducer 与 view-model 纯函数。
//!
//! 约束：本文件不 import ratatui / crossterm / store / App——键盘输入用自带的
//! [`KeyInput`]，数据加载结果用平数据 [`SearchPage`] / [`ContextView`]，副作用只以
//! [`Effect`] 描述、由 glue（mod.rs）执行。业务规则零复制：分页令牌、分支策略、
//! 命中→会话解析全部通过 Effect 交回 Application ADT，本层只持有 UI 状态。

use agent_session_grep_domain::ContextPolicy;
use agent_session_grep_ports::{SearchFacets, SidechainFacet};

/// 命中列表里正文预览的最大字符数（与 human 渲染器的 `SNIPPET_PREVIEW_CHARS` 一致）。
const HIT_SNIPPET_CHARS: usize = 120;

/// 三屏状态机（PRD R2）：Search（输入）→ Results(命中列表) → Context（消息链）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Screen {
    Search,
    Results,
    Context,
}

/// Search-screen facet cycle (mainline filter). Keys: `m` cycles
/// Include → MainOnly → SubagentOnly → Include.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum SidechainMode {
    #[default]
    Include,
    MainOnly,
    SubagentOnly,
}

impl SidechainMode {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Include => "all",
            Self::MainOnly => "main",
            Self::SubagentOnly => "sub",
        }
    }

    pub(crate) fn cycle(self) -> Self {
        match self {
            Self::Include => Self::MainOnly,
            Self::MainOnly => Self::SubagentOnly,
            Self::SubagentOnly => Self::Include,
        }
    }

    pub(crate) fn to_facet(self) -> SidechainFacet {
        match self {
            Self::Include => SidechainFacet::Include,
            Self::MainOnly => SidechainFacet::MainOnly,
            Self::SubagentOnly => SidechainFacet::SubagentOnly,
        }
    }
}

/// Tool-kind cycle for Search facets. Keys: `k` cycles through the closed set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum ToolKindMode {
    #[default]
    Any,
    File,
    Command,
    Web,
    Query,
    Unknown,
}

impl ToolKindMode {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Any => "any",
            Self::File => "file",
            Self::Command => "command",
            Self::Web => "web",
            Self::Query => "query",
            Self::Unknown => "unknown",
        }
    }

    pub(crate) fn cycle(self) -> Self {
        match self {
            Self::Any => Self::File,
            Self::File => Self::Command,
            Self::Command => Self::Web,
            Self::Web => Self::Query,
            Self::Query => Self::Unknown,
            Self::Unknown => Self::Any,
        }
    }

    pub(crate) fn to_filter(self) -> Option<String> {
        match self {
            Self::Any => None,
            other => Some(other.as_str().to_string()),
        }
    }
}

/// 键盘输入的自有枚举：core 保持 crossterm-free，glue 负责 KeyEvent → KeyInput 映射。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KeyInput {
    Char(char),
    Enter,
    Esc,
    Up,
    Down,
    PgUp,
    PgDn,
    Backspace,
    CtrlC,
}

/// 一条检索命中的纯 UI 投影。Resume 只保留 Application 已解析的可用性；
/// core 不读取 source/transcript，也不构造恢复命令。
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct SearchHitView {
    pub id: String,
    pub score: f32,
    pub session_id: Option<String>,
    pub resume_available: bool,
    /// Application 装配的命中正文摘要（ADR-0008，已按 max_snippet_chars 截断）。
    /// 缺失为空串——core 不回读 payload 自己造摘要。
    pub snippet: String,
}

/// 一页检索结果的平数据投影（glue 从 `AppResponse::Search` 构造）。
///
/// `next_cursor`/`has_more` 只来自 App 响应——core 不构造、不解析令牌。
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct SearchPage {
    /// App 钉住排序原样透传；Resume 可用性同样来自 Application 批量解析。
    pub hits: Vec<SearchHitView>,
    pub next_cursor: Option<String>,
    pub has_more: bool,
    pub generation: u64,
    pub truncated: bool,
    pub truncation_reason: Option<String>,
}

/// 固定形状的只读 Resume Metadata 纯 UI 投影。字段缺失保持 `None`，不猜测。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ResumeMetadataView {
    pub session_id: String,
    pub provider_id: Option<String>,
    pub resume_available: bool,
    pub provider_session_id: Option<String>,
    pub original_working_directory: Option<String>,
    pub unavailable_reason: Option<String>,
}

/// Context 屏单条消息的展示事实：角色 + 文本 + 证据精度（wire 字符串，如 `byte`）。
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct ContextMessage {
    pub role: String,
    pub text: String,
    /// 证据精度标记；缺失/legacy 行如实为 `unknown`，绝不臆造。
    pub precision: String,
}

/// 一次会话上下文装配的平数据投影（glue 从 `AppResponse::Context` 构造）。
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct ContextView {
    pub session_id: String,
    pub lines: Vec<ContextMessage>,
    pub truncated: bool,
    pub truncation_reason: Option<String>,
    pub warnings: Vec<String>,
    pub generation: u64,
}

/// UI 状态全集。reducer 之外无人可变更；glue 只读它渲染。
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Model {
    pub screen: Screen,
    /// Search 屏的编辑中输入。
    pub input: String,
    /// 最近一次提交的查询串——续页 Effect 绑定它，而非编辑中的 `input`。
    pub query: String,
    /// 已累积的命中（`n` 追加下一页，提交新查询时清空）。
    pub hits: Vec<SearchHitView>,
    pub selected: usize,
    pub next_cursor: Option<String>,
    pub has_more: bool,
    /// 最近一次翻页的追加事实（如 `+5`）；首页加载为 `None`。
    pub page_note: Option<String>,
    pub context: Option<ContextView>,
    /// 当前 Context Session 的只读 Resume Metadata；切换 Session 时清空重取。
    pub resume: Option<ResumeMetadataView>,
    pub scroll: usize,
    pub policy: ContextPolicy,
    /// Search-screen facet: sidechain filter (cycled with `m`).
    pub sidechain: SidechainMode,
    /// Search-screen facet: tool-kind filter (cycled with `k`).
    pub tool_kind: ToolKindMode,
    /// 最近一次错误或提示（如 `no hits`）；渲染进状态行，不弹窗、不退出。
    pub status: Option<String>,
    /// 最近一次**检索页**的截断事实（PARTIAL 渲染依据），来自 App 响应。
    /// Context 装配的截断/警告留在 [`ContextView`]，不共用这组字段。
    pub truncated: bool,
    pub truncation_reason: Option<String>,
    pub warnings: Vec<String>,
    pub quit: bool,
    pub generation: u64,
}

impl Default for Model {
    fn default() -> Self {
        Model {
            screen: Screen::Search,
            input: String::new(),
            query: String::new(),
            hits: Vec::new(),
            selected: 0,
            next_cursor: None,
            has_more: false,
            page_note: None,
            context: None,
            resume: None,
            scroll: 0,
            policy: ContextPolicy::Mainline,
            sidechain: SidechainMode::Include,
            tool_kind: ToolKindMode::Any,
            status: None,
            truncated: false,
            truncation_reason: None,
            warnings: Vec::new(),
            quit: false,
            generation: 0,
        }
    }
}

/// reducer 的输入事件：按键，或 glue 执行 Effect 后的回填结果。
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Msg {
    Key(KeyInput),
    SearchLoaded(SearchPage),
    ContextLoaded(ContextView),
    ResumeLoaded(ResumeMetadataView),
    /// Effect 执行失败的状态行文本（`error [<code>]: <msg>` 或解析类提示）。
    EffectFailed(String),
}

/// 待 glue 执行的副作用。字段是构造 `AppRequest` 所需的全部事实——
/// core 不接触 App 类型，也绝不在此之外发起数据访问。
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Effect {
    /// 检索：`cursor: None` 为新查询首页，`Some` 为 App 发行的续读令牌原样回传。
    Search {
        query: String,
        cursor: Option<String>,
        facets: SearchFacets,
    },
    /// 命中→distinct Session candidates 解析 + 上下文装配。
    ResolveAndLoadContext {
        hit_id: String,
        policy: ContextPolicy,
    },
    /// 按既知会话 id 重新装配上下文（`f` 切换策略后的 re-fetch）。
    LoadContext {
        session_id: String,
        policy: ContextPolicy,
    },
    /// 通过 Application 固定契约读取当前 Session 的只读 Resume Metadata。
    LoadResumeMetadata { session_id: String },
}

/// 状态转移唯一入口：`(Model, Msg) -> (Model, Option<Effect>)`。纯函数、可单测。
pub(crate) fn update(model: Model, msg: Msg) -> (Model, Option<Effect>) {
    match msg {
        Msg::Key(key) => handle_key(model, key),
        Msg::SearchLoaded(page) => search_loaded(model, page),
        Msg::ContextLoaded(view) => context_loaded(model, view),
        Msg::ResumeLoaded(metadata) => resume_loaded(model, metadata),
        Msg::EffectFailed(text) => effect_failed(model, text),
    }
}

/// 键位表（design §2，冻结）：全局 Ctrl+C 退出；各屏见 match 各臂。
fn handle_key(mut model: Model, key: KeyInput) -> (Model, Option<Effect>) {
    if key == KeyInput::CtrlC {
        model.quit = true;
        return (model, None);
    }
    match model.screen {
        Screen::Search => match key {
            // Facet cycles only when the input box is empty so typing a query
            // that contains `m`/`k` is never intercepted.
            KeyInput::Char('m') if model.input.is_empty() => {
                model.sidechain = model.sidechain.cycle();
                model.status = Some(format!("facet sidechain={}", model.sidechain.as_str()));
                (model, None)
            }
            KeyInput::Char('k') if model.input.is_empty() => {
                model.tool_kind = model.tool_kind.cycle();
                model.status = Some(format!("facet tool_kind={}", model.tool_kind.as_str()));
                (model, None)
            }
            KeyInput::Char(c) => {
                model.input.push(c);
                (model, None)
            }
            KeyInput::Backspace => {
                model.input.pop();
                (model, None)
            }
            // 空白查询不提交（与 App 的 empty-query 校验对齐，省一次必败请求）。
            KeyInput::Enter => {
                if model.input.trim().is_empty() {
                    return (model, None);
                }
                model.query = model.input.clone();
                model.hits.clear();
                model.selected = 0;
                model.next_cursor = None;
                model.has_more = false;
                model.page_note = None;
                model.status = None;
                model.truncated = false;
                model.truncation_reason = None;
                model.warnings.clear();
                // 新查询是一次全新浏览：旧的 ContextView/Resume Metadata 不得残留到
                // 下次进入 Context 屏（Minor-11）。
                model.context = None;
                model.resume = None;
                let effect = Effect::Search {
                    query: model.query.clone(),
                    cursor: None,
                    facets: model.search_facets(),
                };
                (model, Some(effect))
            }
            KeyInput::Esc => {
                if model.input.is_empty() {
                    model.quit = true;
                } else {
                    model.input.clear();
                }
                (model, None)
            }
            _ => (model, None),
        },
        Screen::Results => match key {
            KeyInput::Up => {
                model.selected = model.selected.saturating_sub(1);
                (model, None)
            }
            KeyInput::Down => {
                model.selected = (model.selected + 1).min(model.hits.len().saturating_sub(1));
                (model, None)
            }
            KeyInput::Enter => match model.hits.get(model.selected) {
                Some(hit) => {
                    let effect = Effect::ResolveAndLoadContext {
                        hit_id: hit.id.clone(),
                        policy: model.policy,
                    };
                    (model, Some(effect))
                }
                None => (model, None),
            },
            // 翻页 = 把 App 发行的令牌原样回传；无令牌即无下一页，no-op。
            KeyInput::Char('n') => match model.next_cursor.clone() {
                Some(cursor) if model.has_more => {
                    let effect = Effect::Search {
                        query: model.query.clone(),
                        cursor: Some(cursor),
                        facets: model.search_facets(),
                    };
                    (model, Some(effect))
                }
                _ => (model, None),
            },
            // Re-run current query with cycled facets from Results.
            KeyInput::Char('m') => {
                model.sidechain = model.sidechain.cycle();
                if model.query.trim().is_empty() {
                    model.status = Some(format!("facet sidechain={}", model.sidechain.as_str()));
                    return (model, None);
                }
                model.hits.clear();
                model.selected = 0;
                model.next_cursor = None;
                model.has_more = false;
                model.page_note = None;
                let effect = Effect::Search {
                    query: model.query.clone(),
                    cursor: None,
                    facets: model.search_facets(),
                };
                (model, Some(effect))
            }
            KeyInput::Char('k') => {
                model.tool_kind = model.tool_kind.cycle();
                if model.query.trim().is_empty() {
                    model.status = Some(format!("facet tool_kind={}", model.tool_kind.as_str()));
                    return (model, None);
                }
                model.hits.clear();
                model.selected = 0;
                model.next_cursor = None;
                model.has_more = false;
                model.page_note = None;
                let effect = Effect::Search {
                    query: model.query.clone(),
                    cursor: None,
                    facets: model.search_facets(),
                };
                (model, Some(effect))
            }
            KeyInput::Char('q') => {
                model.quit = true;
                (model, None)
            }
            KeyInput::Esc => {
                model.screen = Screen::Search;
                (model, None)
            }
            _ => (model, None),
        },
        Screen::Context => match key {
            KeyInput::Up => {
                model.scroll = model.scroll.saturating_sub(1);
                (model, None)
            }
            KeyInput::Down => {
                model.scroll = (model.scroll + 1).min(max_scroll(&model));
                (model, None)
            }
            KeyInput::PgUp => {
                model.scroll = model.scroll.saturating_sub(10);
                (model, None)
            }
            KeyInput::PgDn => {
                model.scroll = (model.scroll + 10).min(max_scroll(&model));
                (model, None)
            }
            // 策略切换即重取：分支选择规则在 domain/App，本层只翻开关。
            KeyInput::Char('f') => {
                model.policy = match model.policy {
                    ContextPolicy::Mainline => ContextPolicy::Full,
                    ContextPolicy::Full => ContextPolicy::Mainline,
                };
                match &model.context {
                    Some(view) => {
                        let effect = Effect::LoadContext {
                            session_id: view.session_id.clone(),
                            policy: model.policy,
                        };
                        (model, Some(effect))
                    }
                    None => (model, None),
                }
            }
            KeyInput::Char('q') => {
                model.quit = true;
                (model, None)
            }
            KeyInput::Esc => {
                model.screen = Screen::Results;
                (model, None)
            }
            _ => (model, None),
        },
    }
}

/// 命中加载：追加语义（design §0.7）。首页从空表开始（提交时已清空），
/// 追加页把选中行跳到本页首行；追加页为空（no-op 页）时选中行保持原位置
/// 不回跳（Minor-10）；空结果如实报 `no hits`，界面保持可用。
fn search_loaded(mut model: Model, page: SearchPage) -> (Model, Option<Effect>) {
    let prev = model.hits.len();
    let added = page.hits.len();
    model.hits.extend(page.hits);
    let len = model.hits.len();
    model.selected = if len == 0 {
        0
    } else if added > 0 {
        prev
    } else {
        model.selected // 追加页为空：保持原选中行
    };
    model.next_cursor = page.next_cursor;
    model.has_more = page.has_more;
    model.generation = page.generation;
    model.truncated = page.truncated;
    model.truncation_reason = page.truncation_reason;
    model.warnings.clear();
    model.page_note = if prev > 0 {
        Some(format!("+{added}"))
    } else {
        None
    };
    model.status = if len == 0 {
        Some("no hits".to_string())
    } else {
        None
    };
    model.screen = Screen::Results;
    (model, None)
}

/// 上下文加载：滚动复位；Session 改变时清空旧 metadata，并通过 Application
/// Effect 读取固定 Resume 契约。
///
/// 截断/警告事实**留在** [`ContextView`] 里，不上提到 Model：Model 上那组字段
/// 属于检索页，覆盖掉会让 Esc 回到 Results 后把完整命中列表谎报成 `PARTIAL`
/// （状态行由 [`status_line`] 按当前屏选源）。
fn context_loaded(mut model: Model, view: ContextView) -> (Model, Option<Effect>) {
    let session_id = view.session_id.clone();
    let metadata_is_current = model
        .resume
        .as_ref()
        .is_some_and(|metadata| metadata.session_id == session_id);
    if !metadata_is_current {
        model.resume = None;
    }
    model.generation = view.generation;
    model.context = Some(view);
    model.scroll = 0;
    model.status = None;
    model.screen = Screen::Context;
    let effect = (!metadata_is_current).then_some(Effect::LoadResumeMetadata { session_id });
    (model, effect)
}

/// 仅接受当前 Context Session 的 metadata；同步执行路径之外也不会让陈旧结果串屏。
fn resume_loaded(mut model: Model, metadata: ResumeMetadataView) -> (Model, Option<Effect>) {
    if model
        .context
        .as_ref()
        .is_some_and(|context| context.session_id == metadata.session_id)
    {
        model.resume = Some(metadata);
        model.status = None;
    }
    (model, None)
}

/// Effect 失败只进状态行：UI 继续运行、不换屏、不崩（PRD R4）。
fn effect_failed(mut model: Model, text: String) -> (Model, Option<Effect>) {
    model.status = Some(text);
    (model, None)
}

impl Model {
    /// Project current UI facet toggles into the Application SearchFacets contract.
    pub(crate) fn search_facets(&self) -> SearchFacets {
        SearchFacets {
            sidechain: self.sidechain.to_facet(),
            tool_kind: self.tool_kind.to_filter(),
            tool_name: None,
        }
    }
}

/// Context 屏滚动上界：最后一行仍可见（无内容时为 0）。
fn max_scroll(model: &Model) -> usize {
    model
        .context
        .as_ref()
        .map(|view| view.lines.len().saturating_sub(1))
        .unwrap_or(0)
}

/// 命中列表项：首行 `> <id>  score  session  resume`（选中行前缀 `> `，其余两
/// 空格对齐），有摘要时追加一条缩进的正文预览行。返回的每个元素是一个列表项
/// （可能两行），Session 与 Resume 可用性只展示 Application 已返回的结构化事实。
pub(crate) fn hit_lines(model: &Model) -> Vec<String> {
    model
        .hits
        .iter()
        .enumerate()
        .map(|(i, hit)| {
            let prefix = if i == model.selected { "> " } else { "  " };
            let id = fold_controls(&hit.id);
            let session = hit
                .session_id
                .as_deref()
                .map(fold_controls)
                .unwrap_or_else(|| "—".to_string());
            let resume = if hit.resume_available { "yes" } else { "no" };
            let mut item = format!(
                "{prefix}{id}  score {:.3}  session {session}  resume {resume}",
                hit.score
            );
            // 只有 UUID + score 的命中列表无从判断哪条有用（human 渲染器已按
            // 同一理由补了正文预览，见 human.rs `render_search`）。空白折叠成
            // 单空格，整段按字符（非字节）截断。
            let snippet: String = fold_controls(&hit.snippet)
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ")
                .chars()
                .take(HIT_SNIPPET_CHARS)
                .collect();
            if !snippet.is_empty() {
                item.push_str("\n    ");
                item.push_str(&snippet);
            }
            item
        })
        .collect()
}

/// Resume detail panel：固定字段恒展示，缺失为 `—`；控制字符折叠为空格，
/// 防止 provider-native metadata 改写终端布局。这里不生成命令，也没有 Source path 字段。
pub(crate) fn resume_lines(model: &Model) -> Vec<String> {
    let Some(metadata) = &model.resume else {
        return vec!["Resume Metadata: —".to_string()];
    };
    vec![
        format!(
            "Resume Metadata: {}",
            if metadata.resume_available {
                "available"
            } else {
                "unavailable"
            }
        ),
        format!(
            "provider: {}",
            display_field(metadata.provider_id.as_deref())
        ),
        format!(
            "provider session: {}",
            display_field(metadata.provider_session_id.as_deref())
        ),
        format!(
            "working directory: {}",
            display_field(metadata.original_working_directory.as_deref())
        ),
        format!(
            "unavailable reason: {}",
            display_field(metadata.unavailable_reason.as_deref())
        ),
    ]
}

fn display_field(value: Option<&str>) -> String {
    let Some(value) = value.filter(|value| !value.is_empty()) else {
        return "—".to_string();
    };
    fold_controls(value)
}

/// 控制字符折叠为空格。ratatui 不会替我们做这件事：`unicode-width` 把 ESC 记为
/// 宽度 1，于是 `Paragraph`/`List` 会把它当普通字符写进单元格，后端再原样打印
/// ——真实 transcript 里的终端输出（`\x1b[31;1m   Compiling ...\x1b[0m`）就会被
/// 终端执行，改颜色、移光标、清屏，把整帧 TUI 冲掉。所有非字面量文本（消息
/// 正文/角色、id、错误与警告文本）渲染前必须过这里。
fn fold_controls(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .collect()
}

/// Context 行：`role: 文本首行 [precision]`；unknown 精度如实渲染 `[unknown]`。
pub(crate) fn context_lines(model: &Model) -> Vec<String> {
    match &model.context {
        None => Vec::new(),
        Some(view) => view
            .lines
            .iter()
            .map(|message| {
                let first = message.text.lines().next().unwrap_or("");
                format!(
                    "{}: {} [{}]",
                    fold_controls(&message.role),
                    fold_controls(first),
                    fold_controls(&message.precision)
                )
            })
            .collect(),
    }
}

/// 状态行：generation + 截断（`PARTIAL: <预算旋钮>`）+ 首条警告 + 最近错误/提示。
/// 诚实渲染是硬要求（PRD R3）：截断与降级绝不吞掉——但也绝不把另一屏的截断
/// 事实挂到当前屏上，所以截断/警告按当前屏选源（Context 屏取 [`ContextView`]，
/// 其余屏取检索页留在 Model 上的那组字段）。
pub(crate) fn status_line(model: &Model) -> String {
    let mut parts = vec![format!("gen {}", model.generation)];
    let context = model
        .context
        .as_ref()
        .filter(|_| model.screen == Screen::Context);
    let (truncated, reason, warnings) = match context {
        Some(view) => (
            view.truncated,
            view.truncation_reason.as_deref(),
            view.warnings.as_slice(),
        ),
        None => (
            model.truncated,
            model.truncation_reason.as_deref(),
            model.warnings.as_slice(),
        ),
    };
    if truncated {
        parts.push(format!(
            "PARTIAL: {}",
            fold_controls(reason.unwrap_or("unspecified"))
        ));
    }
    if let Some(warning) = warnings.first() {
        parts.push(format!("warning: {}", fold_controls(warning)));
    }
    if let Some(status) = &model.status {
        parts.push(fold_controls(status));
    }
    parts.join(" | ")
}

/// 标题行：当前屏 + 键位提示 + 诚实的分页/策略事实。
pub(crate) fn title_line(model: &Model) -> String {
    match model.screen {
        Screen::Search => format!(
            "Search - Enter: run  Esc: clear/quit  m: sidechain={}  k: tool={}",
            model.sidechain.as_str(),
            model.tool_kind.as_str()
        ),
        Screen::Results => {
            let more = if model.has_more { "  n: next page" } else { "" };
            let note = model
                .page_note
                .as_deref()
                .map(|n| format!("  [{n}]"))
                .unwrap_or_default();
            format!(
                "Results - {} hits  sidechain={} tool={}{more}{note}  Enter: open  m/k: facets  Esc: back  q: quit",
                model.hits.len(),
                model.sidechain.as_str(),
                model.tool_kind.as_str()
            )
        }
        Screen::Context => {
            let policy = match model.policy {
                ContextPolicy::Mainline => "mainline",
                ContextPolicy::Full => "full",
            };
            let session = model
                .context
                .as_ref()
                .map(|view| fold_controls(&view.session_id))
                .unwrap_or_else(|| "-".to_string());
            format!("Context {session} - policy {policy}  f: toggle, Esc: back, q: quit")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(model: Model, input: KeyInput) -> (Model, Option<Effect>) {
        update(model, Msg::Key(input))
    }

    fn typed(model: Model, text: &str) -> Model {
        text.chars().fold(model, |m, c| key(m, KeyInput::Char(c)).0)
    }

    /// 已输入 "rust" 并提交（hits 已清空、Effect 已发出）的 Search 屏模型。
    fn submitted(query: &str) -> Model {
        let (model, effect) = key(typed(Model::default(), query), KeyInput::Enter);
        assert!(effect.is_some(), "non-empty submit must emit an effect");
        model
    }

    fn hit(id: &str, score: f32) -> SearchHitView {
        SearchHitView {
            id: id.to_string(),
            score,
            session_id: None,
            resume_available: false,
            snippet: String::new(),
        }
    }

    fn page(hits: &[(&str, f32)], cursor: Option<&str>) -> SearchPage {
        SearchPage {
            hits: hits.iter().map(|(id, score)| hit(id, *score)).collect(),
            next_cursor: cursor.map(str::to_string),
            has_more: cursor.is_some(),
            generation: 7,
            truncated: false,
            truncation_reason: None,
        }
    }

    /// 提交 "rust" 后加载一页命中的 Results 屏模型。
    fn results(hits: &[(&str, f32)], cursor: Option<&str>) -> Model {
        let loaded = Msg::SearchLoaded(page(hits, cursor));
        update(submitted("rust"), loaded).0
    }

    fn view(session: &str, lines: usize) -> ContextView {
        ContextView {
            session_id: session.to_string(),
            lines: (0..lines)
                .map(|i| ContextMessage {
                    role: "user".to_string(),
                    text: format!("m{i}"),
                    precision: "byte".to_string(),
                })
                .collect(),
            truncated: false,
            truncation_reason: None,
            warnings: Vec::new(),
            generation: 7,
        }
    }

    fn metadata(session: &str, available: bool) -> ResumeMetadataView {
        ResumeMetadataView {
            session_id: session.to_string(),
            provider_id: Some("synthetic-provider".to_string()),
            resume_available: available,
            provider_session_id: available.then(|| "provider-session-1".to_string()),
            original_working_directory: available.then(|| "C:/workspace/example".to_string()),
            unavailable_reason: (!available).then(|| "metadata_missing".to_string()),
        }
    }

    fn in_context(session: &str, lines: usize) -> Model {
        let loaded = Msg::ContextLoaded(view(session, lines));
        update(results(&[("msg_v1_a", 2.0)], None), loaded).0
    }

    // ---- reducer：Search 屏 ----

    #[test]
    fn typing_and_backspace_edit_input() {
        let model = typed(Model::default(), "abc");
        assert_eq!(model.input, "abc");
        let (model, effect) = key(model, KeyInput::Backspace);
        assert_eq!(model.input, "ab");
        assert!(effect.is_none());
    }

    #[test]
    fn enter_on_empty_input_is_noop() {
        let (model, effect) = key(Model::default(), KeyInput::Enter);
        assert!(effect.is_none());
        assert_eq!(model.screen, Screen::Search);
        // 纯空白同样不提交（App 会拒绝空查询，这里不发必败请求）。
        let (model, effect) = key(typed(Model::default(), "   "), KeyInput::Enter);
        assert!(effect.is_none());
        assert_eq!(model.input, "   ");
    }

    #[test]
    fn enter_submits_search_and_resets_hits() {
        let mut model = typed(Model::default(), "rust");
        model.hits = vec![hit("msg_v1_old", 1.0)];
        model.next_cursor = Some("stale".to_string());
        model.has_more = true;
        let (model, effect) = key(model, KeyInput::Enter);
        assert_eq!(
            effect,
            Some(Effect::Search {
                query: "rust".to_string(),
                cursor: None,
                facets: SearchFacets::default(),
            })
        );
        assert!(model.hits.is_empty());
        assert_eq!(model.query, "rust");
        assert_eq!(model.selected, 0);
        assert!(model.next_cursor.is_none());
        assert!(!model.has_more);
    }

    #[test]
    fn esc_on_search_clears_then_quits() {
        let (model, _) = key(typed(Model::default(), "rust"), KeyInput::Esc);
        assert_eq!(model.input, "");
        assert!(!model.quit);
        let (model, _) = key(model, KeyInput::Esc);
        assert!(model.quit);
    }

    // ---- reducer：SearchLoaded / 翻页 ----

    #[test]
    fn search_loaded_populates_and_moves_to_results() {
        let (model, effect) = update(
            submitted("rust"),
            Msg::SearchLoaded(page(&[("msg_v1_a", 2.0), ("msg_v1_b", 1.0)], Some("tok1"))),
        );
        assert!(effect.is_none());
        assert_eq!(model.screen, Screen::Results);
        assert_eq!(model.hits.len(), 2);
        assert_eq!(model.selected, 0);
        assert_eq!(model.next_cursor.as_deref(), Some("tok1"));
        assert!(model.has_more);
        assert_eq!(model.generation, 7);
        assert!(model.status.is_none());
    }

    #[test]
    fn search_loaded_preserves_session_and_resume_availability() {
        let mut loaded = page(&[], None);
        loaded.hits = vec![SearchHitView {
            id: "msg_v1_resumable".to_string(),
            score: 2.0,
            session_id: Some("ses_v1_resumable".to_string()),
            resume_available: true,
            snippet: String::new(),
        }];

        let (model, effect) = update(submitted("rust"), Msg::SearchLoaded(loaded));

        assert!(effect.is_none());
        assert_eq!(model.hits.len(), 1);
        assert_eq!(
            model.hits[0].session_id.as_deref(),
            Some("ses_v1_resumable")
        );
        assert!(model.hits[0].resume_available);
    }

    #[test]
    fn search_loaded_empty_page_reports_no_hits_and_stays_functional() {
        let loaded = Msg::SearchLoaded(page(&[], None));
        let (model, _) = update(submitted("nope"), loaded);
        assert_eq!(model.screen, Screen::Results);
        assert!(model.hits.is_empty());
        assert_eq!(model.status.as_deref(), Some("no hits"));
        // 空列表上导航/打开都是 no-op，Esc 仍可回到 Search。
        let (model, effect) = key(model, KeyInput::Down);
        assert_eq!(model.selected, 0);
        assert!(effect.is_none());
        let (model, effect) = key(model, KeyInput::Enter);
        assert!(effect.is_none());
        let (model, _) = key(model, KeyInput::Esc);
        assert_eq!(model.screen, Screen::Search);
    }

    #[test]
    fn next_page_emits_search_with_stored_cursor() {
        let model = results(&[("msg_v1_a", 2.0)], Some("tok1"));
        let (_, effect) = key(model, KeyInput::Char('n'));
        assert_eq!(
            effect,
            Some(Effect::Search {
                query: "rust".to_string(),
                cursor: Some("tok1".to_string()),
                facets: SearchFacets::default(),
            })
        );
    }

    #[test]
    fn search_loaded_appends_and_selects_first_new_row() {
        let model = results(&[("msg_v1_a", 2.0), ("msg_v1_b", 1.5)], Some("tok1"));
        let (model, _) = key(model, KeyInput::Char('n'));
        let loaded = Msg::SearchLoaded(page(&[("msg_v1_c", 1.0)], None));
        let (model, _) = update(model, loaded);
        let ids: Vec<&str> = model.hits.iter().map(|hit| hit.id.as_str()).collect();
        assert_eq!(ids, vec!["msg_v1_a", "msg_v1_b", "msg_v1_c"]);
        assert_eq!(model.selected, 2, "selection jumps to first new row");
        assert!(!model.has_more);
        assert!(model.next_cursor.is_none());
        assert_eq!(model.page_note.as_deref(), Some("+1"));
    }

    #[test]
    fn next_page_without_more_is_noop() {
        let model = results(&[("msg_v1_a", 2.0)], None);
        let (model, effect) = key(model, KeyInput::Char('n'));
        assert!(effect.is_none());
        assert_eq!(model.hits.len(), 1);
    }

    #[test]
    fn empty_appended_page_keeps_selection() {
        // Minor-10：追加页为空（0 新命中）时选中行保持原位置，不回跳到上一行。
        let model = results(&[("msg_v1_a", 2.0), ("msg_v1_b", 1.5)], Some("tok1"));
        let (model, _) = key(model, KeyInput::Down); // selected = 1
        let (model, effect) = key(model, KeyInput::Char('n'));
        assert_eq!(
            effect,
            Some(Effect::Search {
                query: "rust".to_string(),
                cursor: Some("tok1".to_string()),
                facets: SearchFacets::default(),
            })
        );
        let (model, _) = update(model, Msg::SearchLoaded(page(&[], None)));
        assert_eq!(model.hits.len(), 2);
        assert_eq!(
            model.selected, 1,
            "empty append page must not move selection"
        );
        assert!(!model.has_more);
    }

    // ---- reducer：Results 导航 ----

    #[test]
    fn selection_saturates_at_list_edges() {
        let model = results(&[("msg_v1_a", 2.0), ("msg_v1_b", 1.0)], None);
        let (model, _) = key(model, KeyInput::Up);
        assert_eq!(model.selected, 0, "Up saturates at the top");
        let (model, _) = key(model, KeyInput::Down);
        assert_eq!(model.selected, 1);
        let (model, _) = key(model, KeyInput::Down);
        assert_eq!(model.selected, 1, "Down saturates at the bottom");
        // 空列表：两个方向都停在 0。
        let empty = results(&[], None);
        let (empty, _) = key(empty, KeyInput::Down);
        assert_eq!(empty.selected, 0);
        let (empty, _) = key(empty, KeyInput::Up);
        assert_eq!(empty.selected, 0);
    }

    #[test]
    fn enter_on_hit_resolves_selected_id() {
        let model = results(&[("msg_v1_a", 2.0), ("msg_v1_b", 1.0)], None);
        let (model, _) = key(model, KeyInput::Down);
        let (_, effect) = key(model, KeyInput::Enter);
        assert_eq!(
            effect,
            Some(Effect::ResolveAndLoadContext {
                hit_id: "msg_v1_b".to_string(),
                policy: ContextPolicy::Mainline,
            })
        );
    }

    // ---- reducer：Context 屏 ----

    #[test]
    fn context_loaded_switches_screen_with_scroll_reset() {
        let mut model = results(&[("msg_v1_a", 2.0)], None);
        model.scroll = 9;
        let (model, effect) = update(model, Msg::ContextLoaded(view("ses_v1_s", 3)));
        assert_eq!(
            effect,
            Some(Effect::LoadResumeMetadata {
                session_id: "ses_v1_s".to_string(),
            })
        );
        assert_eq!(model.screen, Screen::Context);
        assert_eq!(model.scroll, 0);
        assert!(model.context.is_some());
        assert!(model.resume.is_none());
    }

    #[test]
    fn resume_loaded_populates_only_the_current_context_detail() {
        let model = in_context("ses_v1_s", 1);
        let (model, effect) = update(model, Msg::ResumeLoaded(metadata("ses_v1_s", true)));
        assert!(effect.is_none());
        assert!(model.resume.as_ref().is_some_and(|resume| {
            resume.resume_available
                && resume.provider_session_id.as_deref() == Some("provider-session-1")
        }));

        let (model, _) = update(model, Msg::ResumeLoaded(metadata("ses_v1_other", true)));
        assert_eq!(
            model
                .resume
                .as_ref()
                .map(|resume| resume.session_id.as_str()),
            Some("ses_v1_s"),
            "stale metadata must not replace the current detail"
        );
    }

    #[test]
    fn context_reload_for_same_session_does_not_refetch_resume_metadata() {
        let model = in_context("ses_v1_s", 1);
        let (model, _) = update(model, Msg::ResumeLoaded(metadata("ses_v1_s", true)));

        let (model, effect) = update(model, Msg::ContextLoaded(view("ses_v1_s", 2)));

        assert!(effect.is_none());
        assert!(model.resume.is_some());
    }

    #[test]
    fn policy_toggle_refetches_context() {
        let (model, effect) = key(in_context("ses_v1_s", 3), KeyInput::Char('f'));
        assert_eq!(model.policy, ContextPolicy::Full);
        assert_eq!(
            effect,
            Some(Effect::LoadContext {
                session_id: "ses_v1_s".to_string(),
                policy: ContextPolicy::Full,
            })
        );
        let (model, effect) = key(model, KeyInput::Char('f'));
        assert_eq!(model.policy, ContextPolicy::Mainline);
        assert_eq!(
            effect,
            Some(Effect::LoadContext {
                session_id: "ses_v1_s".to_string(),
                policy: ContextPolicy::Mainline,
            })
        );
    }

    #[test]
    fn search_screen_cycles_sidechain_and_tool_kind_facets() {
        let model = Model::default();
        assert_eq!(model.sidechain, SidechainMode::Include);
        assert_eq!(model.tool_kind, ToolKindMode::Any);
        let (model, effect) = key(model, KeyInput::Char('m'));
        assert!(effect.is_none());
        assert_eq!(model.sidechain, SidechainMode::MainOnly);
        let (model, _) = key(model, KeyInput::Char('m'));
        assert_eq!(model.sidechain, SidechainMode::SubagentOnly);
        let (model, _) = key(model, KeyInput::Char('k'));
        assert_eq!(model.tool_kind, ToolKindMode::File);
        let facets = model.search_facets();
        assert_eq!(facets.sidechain, SidechainFacet::SubagentOnly);
        assert_eq!(facets.tool_kind.as_deref(), Some("file"));
        // With empty input, m/k are facet keys (not typed). Typing them only
        // happens once the input is non-empty.
        let model = typed(Model::default(), "x");
        let model = typed(model, "m");
        assert_eq!(model.input, "xm");
        assert_eq!(model.sidechain, SidechainMode::Include);
    }

    #[test]
    fn results_screen_facet_cycle_reissues_search_with_facets() {
        let model = Model {
            screen: Screen::Results,
            query: "rust".into(),
            hits: vec![SearchHitView {
                id: "msg_v1_a".into(),
                score: 1.0,
                session_id: Some("ses_v1_s".into()),
                resume_available: false,
                snippet: String::new(),
            }],
            ..Model::default()
        };
        let (model, effect) = key(model, KeyInput::Char('m'));
        assert_eq!(model.sidechain, SidechainMode::MainOnly);
        assert_eq!(
            effect,
            Some(Effect::Search {
                query: "rust".into(),
                cursor: None,
                facets: SearchFacets {
                    sidechain: SidechainFacet::MainOnly,
                    tool_kind: None,
                    tool_name: None,
                },
            })
        );
        assert!(model.hits.is_empty(), "facet cycle clears prior hits");
    }

    #[test]
    fn title_line_reports_active_facets() {
        let model = Model {
            sidechain: SidechainMode::MainOnly,
            tool_kind: ToolKindMode::Command,
            ..Model::default()
        };
        let title = title_line(&model);
        assert!(title.contains("sidechain=main"), "{title}");
        assert!(title.contains("tool=command"), "{title}");
    }

    #[test]
    fn context_scroll_saturates() {
        let model = in_context("ses_v1_s", 5);
        let (model, _) = key(model, KeyInput::Up);
        assert_eq!(model.scroll, 0, "Up saturates at the top");
        let (model, _) = key(model, KeyInput::PgDn);
        assert_eq!(model.scroll, 4, "PgDn saturates at the last line");
        let (model, _) = key(model, KeyInput::Down);
        assert_eq!(model.scroll, 4, "Down saturates at the last line");
        let (model, _) = key(model, KeyInput::PgUp);
        assert_eq!(model.scroll, 0);
    }

    // ---- reducer：退出与屏间转移 ----

    #[test]
    fn esc_chain_context_results_search_quit() {
        let model = in_context("ses_v1_s", 1);
        let (model, _) = key(model, KeyInput::Esc);
        assert_eq!(model.screen, Screen::Results);
        let (model, _) = key(model, KeyInput::Esc);
        assert_eq!(model.screen, Screen::Search);
        // 提交过的输入仍在：先清空，再退出。
        let (model, _) = key(model, KeyInput::Esc);
        assert_eq!(model.input, "");
        assert!(!model.quit);
        let (model, _) = key(model, KeyInput::Esc);
        assert!(model.quit);
    }

    #[test]
    fn q_quits_on_results_and_context_but_types_on_search() {
        let results_model = results(&[("msg_v1_a", 1.0)], None);
        let (model, _) = key(results_model, KeyInput::Char('q'));
        assert!(model.quit);
        let (model, _) = key(in_context("ses_v1_s", 1), KeyInput::Char('q'));
        assert!(model.quit);
        let (model, _) = key(Model::default(), KeyInput::Char('q'));
        assert!(!model.quit);
        assert_eq!(model.input, "q", "q must type into the search input");
    }

    #[test]
    fn ctrl_c_quits_everywhere() {
        for model in [
            Model::default(),
            results(&[("msg_v1_a", 1.0)], None),
            in_context("ses_v1_s", 1),
        ] {
            let (model, effect) = key(model, KeyInput::CtrlC);
            assert!(model.quit);
            assert!(effect.is_none());
        }
    }

    #[test]
    fn effect_failed_sets_status_and_keeps_screen() {
        let model = results(&[("msg_v1_a", 1.0)], None);
        let failure = Msg::EffectFailed("error [not_found]: gone".to_string());
        let (model, effect) = update(model, failure);
        assert!(effect.is_none());
        assert_eq!(model.screen, Screen::Results);
        assert_eq!(model.status.as_deref(), Some("error [not_found]: gone"));
    }

    #[test]
    fn new_query_submit_clears_stale_context() {
        // Minor-11：提交新查询必须清掉上一次的 ContextView，防止旧上下文
        // 残留到下次进入 Context 屏。
        let model = in_context("ses_v1_s", 3);
        let (model, _) = update(model, Msg::ResumeLoaded(metadata("ses_v1_s", true)));
        assert!(
            model.context.is_some(),
            "precondition: stale context present"
        );
        assert!(model.resume.is_some(), "precondition: stale resume present");
        // 退回 Search 屏并清空残留输入（Esc 链：Context → Results → Search → 清空）。
        let (model, _) = key(model, KeyInput::Esc);
        let (model, _) = key(model, KeyInput::Esc);
        let (model, _) = key(model, KeyInput::Esc);
        assert_eq!(model.screen, Screen::Search);
        assert_eq!(model.input, "");
        let model = typed(model, "fresh");
        let (model, effect) = key(model, KeyInput::Enter);
        assert!(effect.is_some());
        assert!(
            model.context.is_none(),
            "new query must clear stale context"
        );
        assert!(
            model.resume.is_none(),
            "new query must clear stale resume metadata"
        );
        assert_eq!(model.query, "fresh");
    }

    // ---- view-model ----

    #[test]
    fn hit_lines_prefix_selected_row() {
        let mut model = results(&[("msg_v1_a", 2.0), ("msg_v1_b", 1.0)], None);
        model.selected = 1;
        let lines = hit_lines(&model);
        assert!(lines[0].starts_with("  msg_v1_a"), "{lines:?}");
        assert!(lines[1].starts_with("> msg_v1_b"), "{lines:?}");
    }

    #[test]
    fn hit_lines_render_session_resume_availability_and_snippet() {
        // 只有 UUID + score 的列表无从判断哪条有用；摘要与 human 渲染器同源，
        // 空白折叠、按字符截断，控制字符不外泄。
        let mut model = results(&[], None);
        model.hits = vec![SearchHitView {
            id: "msg_v1_a".to_string(),
            score: 2.0,
            session_id: Some("ses_v1_a".to_string()),
            resume_available: true,
            snippet: "  \u{1b}[31mfix the\n\tparser  bug 中文 ".to_string(),
        }];

        let lines = hit_lines(&model);

        assert_eq!(
            lines,
            vec![
                "> msg_v1_a  score 2.000  session ses_v1_a  resume yes\n    [31mfix the parser bug 中文"
            ]
        );

        // 无摘要的命中不追加空行。
        model.hits[0].snippet = "   ".to_string();
        assert_eq!(
            hit_lines(&model),
            vec!["> msg_v1_a  score 2.000  session ses_v1_a  resume yes"]
        );
    }

    #[test]
    fn hit_lines_truncate_snippet_by_characters_not_bytes() {
        let mut model = results(&[], None);
        model.hits = vec![SearchHitView {
            id: "msg_v1_wide".to_string(),
            score: 1.0,
            session_id: None,
            resume_available: false,
            snippet: "中".repeat(400),
        }];

        let preview = hit_lines(&model)[0]
            .split_once("\n    ")
            .expect("snippet row")
            .1
            .to_string();

        assert_eq!(preview.chars().count(), HIT_SNIPPET_CHARS);
        assert!(preview.chars().all(|c| c == '中'));
    }

    #[test]
    fn resume_lines_render_fixed_nullable_fields_and_sanitize_controls() {
        let mut resume = metadata("ses_v1_s", true);
        resume.provider_id = Some("synthetic\nprovider".to_string());
        resume.original_working_directory = Some("C:/work\tspace/example".to_string());
        resume.unavailable_reason = None;
        let model = Model {
            resume: Some(resume),
            ..Model::default()
        };

        let lines = resume_lines(&model);

        assert_eq!(lines[0], "Resume Metadata: available");
        assert_eq!(lines[1], "provider: synthetic provider");
        assert_eq!(lines[3], "working directory: C:/work space/example");
        assert_eq!(lines[4], "unavailable reason: —");
        let rendered = lines.join("\n");
        assert!(!rendered.contains("source_path"));
        assert!(!rendered.contains("transcript"));
    }

    #[test]
    fn context_lines_render_precision_markers() {
        let context = ContextView {
            session_id: "ses_v1_s".to_string(),
            lines: vec![
                ContextMessage {
                    role: "user".to_string(),
                    text: "hello\nworld".to_string(),
                    precision: "byte".to_string(),
                },
                ContextMessage {
                    role: "assistant".to_string(),
                    text: "hi".to_string(),
                    precision: "unknown".to_string(),
                },
            ],
            truncated: false,
            truncation_reason: None,
            warnings: Vec::new(),
            generation: 7,
        };
        let model = Model {
            context: Some(context),
            ..Model::default()
        };
        let lines = context_lines(&model);
        // 只取文本首行；unknown 精度如实渲染 [unknown]。
        assert_eq!(lines[0], "user: hello [byte]");
        assert_eq!(lines[1], "assistant: hi [unknown]");
    }

    #[test]
    fn view_models_fold_control_characters_from_provider_content() {
        // 真实 transcript 会原样保存终端输出：本地 catalog 里的
        // msg_v1_2cf77e63-… 首行就是 `\x1b[31;1m   Compiling krates v0.21.2\x1b[0m`。
        // ratatui 不过滤 ESC（unicode-width 记宽度 1），所以折叠必须发生在这里，
        // 否则转义序列会被终端执行、把整帧冲掉。
        let nasty = "\u{1b}[31;1m   Compiling\u{1b}[0m\u{7}\r\ttail";
        let model = Model {
            screen: Screen::Context,
            hits: vec![SearchHitView {
                id: nasty.to_string(),
                score: 1.0,
                session_id: Some(nasty.to_string()),
                resume_available: true,
                snippet: nasty.to_string(),
            }],
            context: Some(ContextView {
                session_id: nasty.to_string(),
                lines: vec![ContextMessage {
                    role: nasty.to_string(),
                    text: nasty.to_string(),
                    precision: nasty.to_string(),
                }],
                truncated: true,
                truncation_reason: Some(nasty.to_string()),
                warnings: vec![nasty.to_string()],
                generation: 7,
            }),
            truncated: true,
            truncation_reason: Some(nasty.to_string()),
            warnings: vec![nasty.to_string()],
            status: Some(nasty.to_string()),
            ..Model::default()
        };

        // 逐行检查：`hit_lines` 的项内换行是版式结构（首行 + 缩进摘要行），
        // 内容里的控制字符才是缺陷。
        let rows: Vec<String> = [
            hit_lines(&model),
            context_lines(&model),
            vec![status_line(&model), title_line(&model)],
            resume_lines(&model),
        ]
        .concat()
        .iter()
        .flat_map(|item| item.split('\n').map(str::to_string).collect::<Vec<_>>())
        .collect();

        for row in &rows {
            assert!(
                !row.chars().any(char::is_control),
                "view models must not emit control characters: {row:?}"
            );
        }
        assert!(
            rows.iter().any(|row| row.contains("Compiling")),
            "text itself is preserved"
        );
    }

    #[test]
    fn status_line_reports_truncation_per_screen() {
        // Results 屏的状态行只能描述当前那页命中；Context 装配的截断/警告
        // 属于另一屏的数据。Esc 返回 Results 后若还挂着 `PARTIAL: max_messages`，
        // 完整的命中列表就被谎报成不完整（PRD R3 诚实渲染反例）。
        let mut truncated_context = view("ses_v1_s", 2);
        truncated_context.truncated = true;
        truncated_context.truncation_reason = Some("max_messages".to_string());
        truncated_context.warnings =
            vec!["1 of 2 evidence spans have unknown precision".to_string()];
        let model = update(
            results(&[("msg_v1_a", 2.0)], None),
            Msg::ContextLoaded(truncated_context),
        )
        .0;

        let on_context = status_line(&model);
        assert!(on_context.contains("PARTIAL: max_messages"), "{on_context}");
        assert!(on_context.contains("warning: 1 of 2"), "{on_context}");

        let (model, _) = key(model, KeyInput::Esc);
        assert_eq!(model.screen, Screen::Results);
        let on_results = status_line(&model);
        assert!(
            !on_results.contains("PARTIAL"),
            "the search page was complete: {on_results}"
        );
        assert!(
            !on_results.contains("warning:"),
            "context warnings belong to the Context screen: {on_results}"
        );
    }

    #[test]
    fn status_line_reports_partial_truncation() {
        let model = Model {
            generation: 7,
            truncated: true,
            truncation_reason: Some("max_items".to_string()),
            ..Model::default()
        };
        let status = status_line(&model);
        assert!(status.contains("gen 7"), "{status}");
        assert!(status.contains("PARTIAL: max_items"), "{status}");
    }

    #[test]
    fn status_line_renders_error_and_warning() {
        let model = Model {
            status: Some("error [cursor_expired]: cursor expired".to_string()),
            ..Model::default()
        };
        assert!(status_line(&model).contains("error [cursor_expired]"));
        let model = Model {
            warnings: vec!["2 of 3 evidence spans have unknown precision".to_string()],
            ..Model::default()
        };
        assert!(status_line(&model).contains("warning: 2 of 3"));
    }
}
