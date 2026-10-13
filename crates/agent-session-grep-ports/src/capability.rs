//! Provider Capability Matrix（能力矩阵单源权威）。
//!
//! 所有入口（CLI/MCP/Robot/Web）渲染 provider 能力必须读本矩阵，禁止硬编码。
//! 当前已实现的 provider maturity=experimental，按证据逐步晋级
//! （晋级门槛见 `docs/architecture/RFC-0002-provider-adapter-contract.md` §6）。
//!
//! 参考：ctx 的 `provider-support-matrix.json` 格式（idea-only）。

/// Provider 成熟度分级（诚实公开评级，证据晋级，禁止跨级宣传）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderMaturity {
    /// 可发现、可 probe、可解析小 fixture，限制明确。
    Experimental,
    /// 主路径 fixture、golden、contract、只读、增量、source span 均通过。
    Beta,
    /// 完整能力矩阵达成，历史 variant/混合版本/崩溃恢复/正式 target/性能与回滚证据齐备。
    Ga,
    /// 跨平台 Gate D + golden + 全能力链 + owner 晋级决策。
    Certified,
    /// 明确不支持，附原因。
    Unsupported,
}

impl ProviderMaturity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Experimental => "experimental",
            Self::Beta => "beta",
            Self::Ga => "ga",
            Self::Certified => "certified",
            Self::Unsupported => "unsupported",
        }
    }

    /// 目标分级（路线图），不是当前实现状态。
    /// Deferred provider（无 transcript 证据）不声明目标，返回 None。
    pub fn target_for(provider_id: &str) -> Option<Self> {
        match provider_id {
            "claude-code" | "codex" => Some(Self::Certified),
            "grok-build" | "opencode" | "pi" | "antigravity" | "kimi-code" | "openclaw"
            | "hermes" | "qoder" | "tencent-codebuddy" => Some(Self::Beta),
            "aider" | "cline" | "cursor" => Some(Self::Experimental),
            // deepseek-harness / zcode: 无证据 deferred，不设目标
            _ => None,
        }
    }
}

/// 单项能力级别（逐字段）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityLevel {
    /// provider 原生提供。
    Native,
    /// 由内在内容确定性派生。
    Derived,
    /// 部分场景可得。
    Partial,
    /// 该 provider 无此概念。
    Unsupported,
    /// 尚未评估。
    #[default]
    Unknown,
}

/// 单个 provider 的能力声明。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ProviderCapability {
    /// Canonical provider id（如 `claude-code`、`codex`）。
    pub provider_id: String,
    /// Variant 标识（如 `claude-code/jsonl-v1`）。
    pub variant_id: String,
    /// 当前成熟度（事实，非目标）。
    pub maturity: ProviderMaturity,
    /// 发现源目录的能力。
    pub discover: CapabilityLevel,
    /// Probe 能力。
    pub probe: CapabilityLevel,
    /// 解析能力。
    pub parse: CapabilityLevel,
    /// 搜索能力。
    pub search: CapabilityLevel,
    /// 上下文图能力。
    pub context: CapabilityLevel,
    /// Resume 能力。
    pub resume: CapabilityLevel,
    /// Handoff 能力（能否为该 provider 的会话装出带原文证据的 handoff pack）。
    ///
    /// 诚实口径：`handoff` 不是 per-provider 特性。生成器
    /// （`application::handoff_pack::generate_deterministic`）只消费 `SearchHit`
    /// 与权威 source placement，`provenance` 与 `matched_sessions[].provider_id`
    /// 一律为 `None`（搜索型 pack 无单一提供商，不臆造），全流程不读 provider
    /// 身份、无 per-provider 分支。因此"能否装出带证据的 pack"只取决于消息是否
    /// 落库并带 source placement——`parse` 可用即成立。
    ///
    /// 故 14 个已实现 provider 一律 `Derived`（由已落库内容确定性派生），
    /// 此前全列 `Unsupported` 是少报：`asg handoff` 是已发布命令，对 codex
    /// （JSONL）、aider（markdown，native_id 恒空）、opencode（SQLite）三种结构
    /// 迥异的真实 golden 源实测均产出 `confidence: high` 的带证据 pack。
    /// 由 `handoff_pack_generation_is_provider_independent` 守护。
    pub handoff: CapabilityLevel,
    /// 工具活动提取能力。
    pub tool_activity: CapabilityLevel,
    /// Token 用量提取能力（usage 维度：只记录 provider 格式明确给出的数字，
    /// 累计量转增量必须单调校验，绝不按文本长度等代理估算）。
    pub usage: CapabilityLevel,
    /// Source span 精度。
    pub source_span: CapabilityLevel,
    /// 增量同步能力（未变化的源 resync 是否为 no-op）。
    ///
    /// 诚实口径：与 [`Self::handoff`] 同理，`incremental` 也不是 per-provider
    /// 特性。判定链全在 composition root + store 层：`sync` 先读 `source_scans`
    /// 的 `(len_bytes, fingerprint)` 缓存，与当次快照的 BLAKE3 指纹比对，相同则
    /// **跳过 parse**（`unchanged` 上报已存消息数），再由
    /// `commit_source_batches_if_changed` 做内容级 no-op 判定、不推进 generation。
    /// 这条链上没有任何 per-provider 分支，adapter 也不参与。
    ///
    /// 故 14 个已实现 provider 一律 `Derived`——由源字节确定性派生，而非 provider
    /// 原生提供。此前 claude-code/codex 记 `Native`、其余 12 个记 `Unsupported`
    /// 都不准：前者把 store 层能力误记为 provider 原生，后者是少报（12 个
    /// provider 的真实 golden 源实测 resync 均为 `committed=0` /
    /// `unchanged=N` / generation 不变）。由 e2e
    /// `capability_incremental_claim_matches_real_resync_for_every_provider`
    /// 逐 provider 实测守护。
    pub incremental: CapabilityLevel,
}

impl ProviderCapability {
    #[allow(dead_code)]
    fn unknown(provider_id: &str) -> Self {
        Self {
            provider_id: provider_id.to_string(),
            variant_id: String::new(),
            maturity: ProviderMaturity::Unsupported,
            discover: CapabilityLevel::Unknown,
            probe: CapabilityLevel::Unknown,
            parse: CapabilityLevel::Unknown,
            search: CapabilityLevel::Unknown,
            context: CapabilityLevel::Unknown,
            resume: CapabilityLevel::Unknown,
            handoff: CapabilityLevel::Unknown,
            tool_activity: CapabilityLevel::Unknown,
            usage: CapabilityLevel::Unknown,
            source_span: CapabilityLevel::Unknown,
            incremental: CapabilityLevel::Unknown,
        }
    }
}

/// 全部 provider 的能力矩阵。入口层渲染 provider 能力的唯一来源。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProviderCapabilityMatrix {
    pub providers: Vec<ProviderCapability>,
}

const SEARCH_PROVIDER_ALIASES: &[(&str, &str)] = &[("claude", "claude-code")];

fn search_provider_registry() -> &'static ProviderCapabilityMatrix {
    static MATRIX: std::sync::OnceLock<ProviderCapabilityMatrix> = std::sync::OnceLock::new();
    MATRIX.get_or_init(ProviderCapabilityMatrix::current)
}

fn is_filterable(provider: &ProviderCapability) -> bool {
    provider.maturity != ProviderMaturity::Unsupported
        && !provider.variant_id.is_empty()
        && matches!(
            provider.parse,
            CapabilityLevel::Native | CapabilityLevel::Derived | CapabilityLevel::Partial
        )
        && matches!(
            provider.search,
            CapabilityLevel::Native | CapabilityLevel::Derived | CapabilityLevel::Partial
        )
}

/// Resolve canonical IDs and supported historical aliases from the same
/// capability rows that advertise searchable, ingestible providers.
pub fn canonical_search_provider_id(value: &str) -> Option<&'static str> {
    let canonical = SEARCH_PROVIDER_ALIASES
        .iter()
        .find_map(|(alias, canonical)| (*alias == value).then_some(*canonical))
        .unwrap_or(value);
    search_provider_registry()
        .providers
        .iter()
        .find(|provider| provider.provider_id == canonical && is_filterable(provider))
        .map(|provider| provider.provider_id.as_str())
}

/// Accepted request spellings for CLI help, MCP schemas and runtime validation.
pub fn search_provider_filter_values() -> Vec<&'static str> {
    let mut values: Vec<_> = search_provider_registry()
        .providers
        .iter()
        .filter(|provider| is_filterable(provider))
        .map(|provider| provider.provider_id.as_str())
        .collect();
    values.extend(
        SEARCH_PROVIDER_ALIASES
            .iter()
            .filter_map(|(alias, canonical)| {
                canonical_search_provider_id(canonical).map(|_| *alias)
            }),
    );
    values.sort_unstable();
    values.dedup();
    values
}

impl ProviderCapabilityMatrix {
    /// 返回当前 16 个 provider 的能力矩阵（14 个已实现 + 2 个 deferred）。
    /// deferred provider（deepseek-harness/zcode）无 transcript 证据，
    /// 保持 Unsupported 不宣传。
    pub fn current() -> Self {
        Self {
            providers: vec![
                ProviderCapability {
                    provider_id: "aider".into(),
                    variant_id: "aider/chat-history-md-v1".into(),
                    maturity: ProviderMaturity::Experimental,
                    // `PROVIDER_DISCOVERY_ROOTS` 按构造是 home 相对的单根表，而
                    // aider 的 canonical 源是**每个 repo 各一份**的
                    // `<repo>/.aider.chat.history.md`——home 下没有汇总目录可登记。
                    // 本 adapter 所引上游 agentsview 也不是查表：它从任意用户给定
                    // 根递归找该文件名，并显式跳过 macOS 受保护的一级 home 目录
                    // （`aiderProtectedHomeDirs`）。这是"结构上不适用本表"，不是
                    // "根未知"：真要支持得先有 repo 集合来源（workspace 列表），
                    // 属独立任务。当前经显式 `sync <file>` 路径完整可用。
                    discover: CapabilityLevel::Unsupported,
                    probe: CapabilityLevel::Native,
                    parse: CapabilityLevel::Native,
                    search: CapabilityLevel::Native,
                    context: CapabilityLevel::Unsupported,
                    resume: CapabilityLevel::Unsupported,
                    handoff: CapabilityLevel::Derived,
                    // adapter 从不调用 `emit_activity`（零调用点），且消息以空
                    // native id 上报——composition root 对空锚点 fail-closed 丢弃，
                    // 故即便未来 emit 也无法附着。如实降级为 unsupported。
                    tool_activity: CapabilityLevel::Unsupported,
                    // Markdown chat history 没有任何 token 用量记录（aider 的
                    // 模型统计不在 `.aider.chat.history.md` 内），格式无此概念。
                    usage: CapabilityLevel::Unsupported,
                    source_span: CapabilityLevel::Derived,
                    incremental: CapabilityLevel::Derived,
                },
                ProviderCapability {
                    provider_id: "claude-code".into(),
                    variant_id: "claude-code/jsonl-v1".into(),
                    maturity: ProviderMaturity::Experimental,
                    discover: CapabilityLevel::Native,
                    probe: CapabilityLevel::Native,
                    parse: CapabilityLevel::Native,
                    search: CapabilityLevel::Native,
                    context: CapabilityLevel::Native,
                    resume: CapabilityLevel::Derived,
                    handoff: CapabilityLevel::Derived,
                    tool_activity: CapabilityLevel::Partial,
                    // assistant 记录自带 `message.usage`（input/output/
                    // cache_read/cache_creation 四桶，provider 原生逐消息给出），
                    // adapter 按记录 uuid 锚定提取——Observed，不推算。
                    usage: CapabilityLevel::Native,
                    source_span: CapabilityLevel::Native,
                    incremental: CapabilityLevel::Derived,
                },
                ProviderCapability {
                    provider_id: "codex".into(),
                    variant_id: "codex/rollout-jsonl-v1".into(),
                    maturity: ProviderMaturity::Experimental,
                    discover: CapabilityLevel::Native,
                    probe: CapabilityLevel::Native,
                    parse: CapabilityLevel::Native,
                    search: CapabilityLevel::Native,
                    // Codex rollout 是线性序列，不带显式 threading 边：adapter 对每条
                    // 消息硬编码 `parent_native_id: None`（见 provider-codex 模块文档
                    // "无 `parentUuid`……故 parent 一律 `None`（诚实：不编造上层可推断
                    // 的线性链）"）。没有边就没有上下文图可组装——`context` 从
                    // Native 降级为 Unsupported，此前的 Native 是虚报，由
                    // `capability_context_claim_matches_pinned_golden_parent_links` 抓出。
                    context: CapabilityLevel::Unsupported,
                    resume: CapabilityLevel::Derived,
                    handoff: CapabilityLevel::Derived,
                    tool_activity: CapabilityLevel::Partial,
                    // rollout 的 `event_msg/token_count` 只给累计总量
                    // （total_token_usage/last_token_usage），adapter 用单调校验
                    // + stale 回归判定把累计量转成增量事件（session 级锚定）——
                    // Derived，回归即丢弃、绝不编造。
                    usage: CapabilityLevel::Derived,
                    source_span: CapabilityLevel::Native,
                    incremental: CapabilityLevel::Derived,
                },
                ProviderCapability {
                    provider_id: "grok-build".into(),
                    variant_id: "grok-build/acp-updates-v1".into(),
                    maturity: ProviderMaturity::Experimental,
                    // `PROVIDER_DISCOVERY_ROOTS` 注册 `~/.grok/sessions`（JSONL 源）。
                    discover: CapabilityLevel::Native,
                    probe: CapabilityLevel::Native,
                    parse: CapabilityLevel::Native,
                    search: CapabilityLevel::Native,
                    context: CapabilityLevel::Unsupported,
                    // resume 命令已由 application::resume builder 支持（grok --resume），
                    // 与矩阵一致标记 Derived（audit P1-2 drift 测试守护）。
                    resume: CapabilityLevel::Derived,
                    handoff: CapabilityLevel::Derived,
                    // ACP 流确有结构化工具记录（user_message_chunk 的
                    // `content._meta.bashCommand`，adapter 作为非对话元 chunk 跳过），
                    // 但格式无 per-message native id（promptId/promptIndex 是
                    // prompt 级分组键）——消息以空 native id 上报，活动无法锚定
                    // （staging fail-closed 丢弃）。如实保持 Unsupported。
                    tool_activity: CapabilityLevel::Unsupported,
                    // ACP 流确有 `_meta.totalTokens`（chunk 级累计，格式事实，
                    // 见 grok-build-reference 研究），但 adapter 当前不解析该字段
                    // 且消息无 per-message native id——本切片不宣称 usage 能力。
                    usage: CapabilityLevel::Unsupported,
                    source_span: CapabilityLevel::Native,
                    incremental: CapabilityLevel::Derived,
                },
                ProviderCapability {
                    provider_id: "pi".into(),
                    variant_id: "pi/session-jsonl-v1".into(),
                    maturity: ProviderMaturity::Experimental,
                    // `PROVIDER_DISCOVERY_ROOTS` 注册 `~/.pi/agent/sessions`（JSONL 源，
                    // 按 cwd 编码分子目录，递归扫描覆盖）。
                    discover: CapabilityLevel::Native,
                    probe: CapabilityLevel::Native,
                    parse: CapabilityLevel::Native,
                    search: CapabilityLevel::Native,
                    // 格式**确有** threading 边：v2/v3 逐条记录带 `id` + 显式
                    // `parentId`，同 parentId 的多个子记录就是分支（证据：
                    // cc-sessions-viewer `pi.rs parse_entries`、ctx
                    // `pi-session.jsonl`、Recall/fast-resume/hstry 的 pi adapter）。
                    // 仍记 Unsupported 的原因不是"没有边"，而是**发不出边**：
                    // `message_edges` 的父指针经 `derive_message_id` →
                    // `StableId::native(IdKind::Message, ..)` 逐字采用 native id，
                    // 且与 Session 不同**没有 provider/安装命名空间**。真实 Pi 的
                    // entry id 是 8 位十六进制（32 bit，本机证据：agent-sessions 的
                    // pi stage0 fixture 里 `f7c7091e`/`3a59c5dd`），只在单文件内
                    // 唯一——提升为全局消息身份会让两个会话的不同消息落到同一实体。
                    // adapter 因此把"这是 v2/v3、树未建模"写成显式 ParseReport
                    // 诊断（钉住测试见 crate golden.rs 的 v3 fixture），不静默降级。
                    // 要升级 context 必须先在 composition root 落地 document-scoped
                    // native 消息身份——共享契约改动，不是 per-adapter 改动。
                    context: CapabilityLevel::Unsupported,
                    resume: CapabilityLevel::Derived,
                    handoff: CapabilityLevel::Derived,
                    // 格式确有结构化工具记录（v3 的 assistant content 带
                    // `{type:"toolCall"}` 块，`message.role:"toolResult"` 独立成条，
                    // 证据同上），但 adapter 既不解析这些块、也不 emit_activity，
                    // 且消息以空 native id 上报——活动无法锚定（staging fail-closed
                    // 丢弃）。如实保持 Unsupported：这是"未提取"，不是"格式没有"。
                    // 钉住测试见 crate golden.rs（语料只含 text 块 + 零 activity）。
                    tool_activity: CapabilityLevel::Unsupported,
                    // 格式确有 `message.usage`（input/output/total_tokens，证据：
                    // ctx provider-history fixture `pi-session.jsonl`），但消息以
                    // 空 native id 上报——usage 事件无法锚定（fail-closed 丢弃）。
                    // 待 adapter 提供消息身份后再提取。
                    usage: CapabilityLevel::Unsupported,
                    source_span: CapabilityLevel::Native,
                    incremental: CapabilityLevel::Derived,
                },
                ProviderCapability {
                    provider_id: "kimi-code".into(),
                    variant_id: "kimi-code/wire-jsonl-v1".into(),
                    maturity: ProviderMaturity::Experimental,
                    // `PROVIDER_DISCOVERY_ROOTS` 注册 `~/.kimi-code/sessions`（JSONL 源）。
                    discover: CapabilityLevel::Native,
                    probe: CapabilityLevel::Native,
                    parse: CapabilityLevel::Native,
                    search: CapabilityLevel::Native,
                    context: CapabilityLevel::Unsupported,
                    // resume 命令已由 application::resume builder 支持
                    // （`kimi --session <id>`）。证据：fast-resume kimi.rs
                    // `resume_command`，同源已核验（fast-resume 解析
                    // `$KIMI_CODE_HOME/sessions/**/agents/main/wire.jsonl` +
                    // `state.json`，与本 provider 的 wire.jsonl 面同一 CLI）。
                    resume: CapabilityLevel::Derived,
                    handoff: CapabilityLevel::Derived,
                    // wire.jsonl 的 `context.append_loop_event` 确承载 step/tool
                    // 事件（含 tool.call/tool.result），但本切片不解析 loop 事件，
                    // 且 append_message 记录无 per-message native id——活动无法
                    // 锚定（staging fail-closed 丢弃）。如实保持 Unsupported。
                    tool_activity: CapabilityLevel::Unsupported,
                    // wire.jsonl 确有 `usage.record` 行（{model, usage:{input_tokens,
                    // output_tokens}}，证据：ctx provider-history fixture
                    // `kimi-code-cli/.../wire.jsonl`），但它是 model 级请求记录、
                    // 不关联消息，且本切片只解析 append_message——待 loop 事件
                    // 切片落地后再提取。
                    usage: CapabilityLevel::Unsupported,
                    source_span: CapabilityLevel::Native,
                    incremental: CapabilityLevel::Derived,
                },
                ProviderCapability {
                    provider_id: "qoder".into(),
                    variant_id: "qoder/transcript-jsonl-v1".into(),
                    maturity: ProviderMaturity::Experimental,
                    // `PROVIDER_DISCOVERY_ROOTS` 注册 `~/.qoder/projects`（transcript
                    // JSONL 树）。该 root 只覆盖官方 transcript 面，不含 Qoder
                    // Electron 端的 SQLite 会话库（见 adapter 模块文档）。
                    discover: CapabilityLevel::Native,
                    probe: CapabilityLevel::Native,
                    parse: CapabilityLevel::Native,
                    search: CapabilityLevel::Native,
                    context: CapabilityLevel::Unsupported,
                    // resume 保持 Unknown：参考项目（fast-resume/
                    // sessiongrep/ctx/agf/cc-switch/AgentRecall）均无 Qoder
                    // resume 命令证据；AgentRecall 明确标 `resume: false`、
                    // `resumeTarget: null`。无权威命令就不编造。
                    resume: CapabilityLevel::Unknown,
                    handoff: CapabilityLevel::Derived,
                    // transcript 确有 `tool_use`/`tool_result` 记录类型（当前作为
                    // 非对话记录跳过），但 user/assistant 记录无 per-message
                    // native id——活动无法锚定（staging fail-closed 丢弃）。
                    // 如实保持 Unsupported。
                    tool_activity: CapabilityLevel::Unsupported,
                    // transcript 记录（session_meta/user/assistant/progress/
                    // tool_use/tool_result）无任何 token 用量字段证据（ctx
                    // provider-history fixture `qoder-session-1.jsonl` 全文无
                    // usage/token 键）——格式无此概念。
                    usage: CapabilityLevel::Unsupported,
                    source_span: CapabilityLevel::Native,
                    incremental: CapabilityLevel::Derived,
                },
                ProviderCapability {
                    provider_id: "openclaw".into(),
                    variant_id: "openclaw/session-jsonl-v3".into(),
                    maturity: ProviderMaturity::Experimental,
                    // `PROVIDER_DISCOVERY_ROOTS` 注册 `~/.openclaw/agents`，JSONL 源可被
                    // discover 扫描收集；此前记为 unsupported 与代码相反。
                    discover: CapabilityLevel::Native,
                    probe: CapabilityLevel::Native,
                    parse: CapabilityLevel::Native,
                    search: CapabilityLevel::Native,
                    context: CapabilityLevel::Unsupported,
                    resume: CapabilityLevel::Unsupported,
                    handoff: CapabilityLevel::Derived,
                    // 文档化的 v3 格式知识（session/message 记录，content 为字符串
                    // 或 {type:"text"} 块）不含任何结构化工具调用记录，且消息以空
                    // native id 上报——如实保持 Unsupported（钉住测试见 crate
                    // golden.rs）。
                    tool_activity: CapabilityLevel::Unsupported,
                    // 文档化的 v3 格式知识（session/message 记录）不含 token
                    // 用量字段——格式无此概念。
                    usage: CapabilityLevel::Unsupported,
                    source_span: CapabilityLevel::Native,
                    incremental: CapabilityLevel::Derived,
                },
                ProviderCapability {
                    provider_id: "tencent-codebuddy".into(),
                    variant_id: "tencent-codebuddy/cli-jsonl-v1".into(),
                    maturity: ProviderMaturity::Experimental,
                    // `PROVIDER_DISCOVERY_ROOTS` 注册 `~/.codebuddy/projects`（JSONL 源）。
                    discover: CapabilityLevel::Native,
                    probe: CapabilityLevel::Native,
                    parse: CapabilityLevel::Native,
                    search: CapabilityLevel::Native,
                    context: CapabilityLevel::Unsupported,
                    // resume 命令已由 application::resume builder 支持
                    // （`codebuddy --resume <id>`）。证据：AgentRecall 对
                    // codebuddy-cli（读 `~/.codebuddy/projects/*.jsonl`，与本
                    // provider 同一源面）生成 `cd <repo> && codebuddy --resume
                    // <id>`，并识别真实 `codebuddy --resume <id>` 进程行。
                    resume: CapabilityLevel::Derived,
                    handoff: CapabilityLevel::Derived,
                    // 文档化的格式知识（type:"message" + 顶层 role/content，content
                    // 为字符串或 {type:"text"} 数组）不含结构化工具调用记录形状，
                    // 且消息以空 native id 上报——如实保持 Unsupported（钉住测试
                    // 见 crate golden.rs）。
                    tool_activity: CapabilityLevel::Unsupported,
                    // CLI JSONL 的 assistant 记录确有内嵌 `message.usage`
                    // （input/output/total_tokens，证据：ctx native_real_shapes
                    // 真实形态测试），但消息以空 native id 上报——usage 事件无法
                    // 锚定（fail-closed 丢弃）。待 adapter 提供消息身份后再提取。
                    usage: CapabilityLevel::Unsupported,
                    source_span: CapabilityLevel::Native,
                    incremental: CapabilityLevel::Derived,
                },
                ProviderCapability {
                    provider_id: "opencode".into(),
                    variant_id: "opencode/sqlite-v1".into(),
                    maturity: ProviderMaturity::Experimental,
                    // `PROVIDER_DISCOVERY_ROOTS` 注册 `~/.local/share/opencode` 并声明
                    // 扩展名 `db`：源是单个 SQLite `opencode.db`，`-wal`/`-shm` 旁文件的
                    // extension 不是 `db`，精确匹配天然排除。
                    discover: CapabilityLevel::Native,
                    probe: CapabilityLevel::Native,
                    parse: CapabilityLevel::Native,
                    search: CapabilityLevel::Native,
                    context: CapabilityLevel::Unsupported,
                    // resume 命令已由 application::resume builder 支持：
                    // fast-resume opencode.rs `resume_command` =
                    // `opencode <directory> --session <id>`（directory 为
                    // positional 参数，来自会话原始工作目录；同一 SQLite 源面）。
                    // 目录缺失时省略 positional 参数（cc-switch `opencode -s
                    // <id>` / agf 同形的已验证形态）。
                    resume: CapabilityLevel::Derived,
                    handoff: CapabilityLevel::Derived,
                    tool_activity: CapabilityLevel::Unsupported,
                    // opencode.db 的 message 行 data JSON 确有 `tokens`
                    // {input, output, reasoning}（证据：hstry opencode adapter
                    // 读取同一列聚合 tokensIn/tokensOut），但本 adapter 当前只
                    // 查询对话字段——待切片读取 data 列后再提取。
                    usage: CapabilityLevel::Unsupported,
                    source_span: CapabilityLevel::Unsupported,
                    incremental: CapabilityLevel::Derived,
                },
                ProviderCapability {
                    provider_id: "cline".into(),
                    variant_id: "cline/api-conversation-history-v1".into(),
                    maturity: ProviderMaturity::Experimental,
                    // `PROVIDER_DISCOVERY_ROOTS` 注册 `~/.cline/data/tasks`（扩展名
                    // `json`）：ctx 的 history_locations 与其 fixture 布局一致地把
                    // task 目录放在该根下。同目录的三个旁文件都不是 role 数组，
                    // 本 adapter 的 probe 如实拒绝，故登记该根不会误收。
                    discover: CapabilityLevel::Native,
                    probe: CapabilityLevel::Native,
                    parse: CapabilityLevel::Native,
                    search: CapabilityLevel::Native,
                    context: CapabilityLevel::Unsupported,
                    resume: CapabilityLevel::Unsupported,
                    handoff: CapabilityLevel::Derived,
                    tool_activity: CapabilityLevel::Unsupported,
                    // api_conversation_history 的 assistant 消息确有 `usage`
                    // 字段（证据：ctx task_json provider 读取 `.get("usage")`），
                    // 但消息无 per-message native id——usage 事件无法锚定
                    // （fail-closed 丢弃）。待 adapter 提供消息身份后再提取。
                    usage: CapabilityLevel::Unsupported,
                    source_span: CapabilityLevel::Unsupported,
                    incremental: CapabilityLevel::Derived,
                },
                ProviderCapability {
                    provider_id: "hermes".into(),
                    variant_id: "hermes/session-json-v1".into(),
                    maturity: ProviderMaturity::Experimental,
                    // `PROVIDER_DISCOVERY_ROOTS` 注册 `~/.hermes/sessions`（扩展名
                    // `json`）：该 root 由 adapter 所引 hstry 上游硬编码并自证归属，
                    // 不是本机推测。
                    discover: CapabilityLevel::Native,
                    probe: CapabilityLevel::Native,
                    parse: CapabilityLevel::Native,
                    search: CapabilityLevel::Native,
                    context: CapabilityLevel::Unsupported,
                    // resume 保持 Unknown：参考项目证据冲突——agf
                    // `hermes --resume <id>`（SQLite state.db 面）、agent-sessions
                    // `hermes --resume <id>`/`--continue`（附带"取决于所装 CLI
                    // 是否暴露该 flag"的保留声明）、hstry `hermes --session
                    // <id>`（其 resume 配置对 pi 已证不可靠：`pi --session
                    // {session_path}` 与验证形态不符），而读同一 `~/.hermes/
                    // sessions` JSON 面的 cc-switch 与 AgentRecall 均无 resume
                    // 命令（None / `resume: false`）。无权威结论就不编造。
                    resume: CapabilityLevel::Unknown,
                    handoff: CapabilityLevel::Derived,
                    tool_activity: CapabilityLevel::Unsupported,
                    // 文档化的 session JSON 消息形态（{role, content, reasoning?,
                    // timestamp?, tool_call_id?, tool_calls?}）不含 token 用量
                    // 字段；hstry 上游同样不提取——格式无此概念。
                    usage: CapabilityLevel::Unsupported,
                    source_span: CapabilityLevel::Unsupported,
                    incremental: CapabilityLevel::Derived,
                },
                ProviderCapability {
                    provider_id: "antigravity".into(),
                    variant_id: "antigravity/transcript-jsonl-v1".into(),
                    maturity: ProviderMaturity::Experimental,
                    // `PROVIDER_DISCOVERY_ROOTS` 注册 `~/.gemini/antigravity-cli/brain`（JSONL 源）。
                    discover: CapabilityLevel::Native,
                    probe: CapabilityLevel::Native,
                    parse: CapabilityLevel::Native,
                    search: CapabilityLevel::Native,
                    context: CapabilityLevel::Unsupported,
                    // resume 命令已由 application::resume builder 支持
                    // （`agy --conversation <id>`）。证据：fast-resume
                    // antigravity.rs `resume_command`（同一
                    // `~/.gemini/antigravity-cli` 源面）与 agent-sessions 的
                    // AntigravityResumeCommandBuilder（并以 `agy --help` 校验
                    // `--conversation` 存在）双源一致。
                    resume: CapabilityLevel::Derived,
                    handoff: CapabilityLevel::Derived,
                    // step 记录确带 `tool_calls` 字段（adapter 忽略），但
                    // `step_index` 是文件内序号而非跨文档 durable id（synthetic
                    // 值会碰撞），消息以空 native id 上报——活动无法锚定
                    // （staging fail-closed 丢弃）。如实保持 Unsupported。
                    tool_activity: CapabilityLevel::Unsupported,
                    // transcript.jsonl step 记录无 token 用量字段证据（ctx
                    // provider-history fixture `transcript_full.jsonl` 全文无
                    // usage/token 键）——格式无此概念。
                    usage: CapabilityLevel::Unsupported,
                    // 行式 JSONL：adapter 逐记录发 `span: Some((start, end))`，
                    // golden `golden_spans_slice_back_to_exact_source_lines`
                    // 逐字节校验切片。此前记为 unsupported 与代码相反。
                    source_span: CapabilityLevel::Native,
                    incremental: CapabilityLevel::Derived,
                },
                ProviderCapability {
                    provider_id: "cursor".into(),
                    variant_id: "cursor/vscdb-chat-v1".into(),
                    maturity: ProviderMaturity::Experimental,
                    // 本 adapter 的面是 VS Code workspaceStorage 的 `state.vscdb`
                    // （`ItemTable` KV + chatdata/prompts 键），其 workspaceStorage
                    // 布局无本机证据，不猜路径。
                    //
                    // 另有一个**看似可登记但实则错位**的根：fast-resume 的
                    // `cursor_chats_dir()` = `~/.cursor/chats`，下面是
                    // `<id>/store.db`。那是 Cursor **CLI** 的库，schema 为
                    // `meta`/`blobs` 两张 KV 表，没有 `ItemTable`——本 adapter 的
                    // probe 会一律 `AmbiguousVariant` 拒绝。登记它只会让扫描
                    // "完整地"收下一批注定解析失败的源，并对外宣称 discover 可用，
                    // 比留 unsupported 更不诚实。该面需要独立的 CLI variant，未实现。
                    discover: CapabilityLevel::Unsupported,
                    probe: CapabilityLevel::Native,
                    parse: CapabilityLevel::Native,
                    search: CapabilityLevel::Native,
                    context: CapabilityLevel::Unsupported,
                    // resume 保持 Unknown：fast-resume 的 `agent --resume <id>`
                    // 属 Cursor **CLI**（`~/.cursor/chats/*/store.db` 面），与
                    // 本 provider 的 VS Code workspaceStorage `state.vscdb`
                    // 面不同源；该 CLI variant 未实现，不能借其命令。
                    resume: CapabilityLevel::Unknown,
                    handoff: CapabilityLevel::Derived,
                    tool_activity: CapabilityLevel::Unsupported,
                    // chatdata 确有 bubble `tokenCount` {inputTokens, outputTokens}
                    // 与 composer 级 `promptTokenBreakdown`（证据：Recall
                    // cursor.rs 读取同一 chatdata 面），但本 adapter 当前只读
                    // type/text/timing——待切片读取用量字段后再提取。
                    usage: CapabilityLevel::Unsupported,
                    source_span: CapabilityLevel::Unsupported,
                    incremental: CapabilityLevel::Derived,
                },
                ProviderCapability {
                    provider_id: "deepseek-harness".into(),
                    variant_id: String::new(),
                    maturity: ProviderMaturity::Unsupported,
                    discover: CapabilityLevel::Unknown,
                    probe: CapabilityLevel::Unknown,
                    parse: CapabilityLevel::Unknown,
                    search: CapabilityLevel::Unknown,
                    context: CapabilityLevel::Unknown,
                    resume: CapabilityLevel::Unknown,
                    handoff: CapabilityLevel::Unknown,
                    tool_activity: CapabilityLevel::Unknown,
                    usage: CapabilityLevel::Unknown,
                    source_span: CapabilityLevel::Unknown,
                    incremental: CapabilityLevel::Unknown,
                },
                ProviderCapability {
                    provider_id: "zcode".into(),
                    variant_id: String::new(),
                    maturity: ProviderMaturity::Unsupported,
                    discover: CapabilityLevel::Unknown,
                    probe: CapabilityLevel::Unknown,
                    parse: CapabilityLevel::Unknown,
                    search: CapabilityLevel::Unknown,
                    context: CapabilityLevel::Unknown,
                    resume: CapabilityLevel::Unknown,
                    handoff: CapabilityLevel::Unknown,
                    tool_activity: CapabilityLevel::Unknown,
                    usage: CapabilityLevel::Unknown,
                    source_span: CapabilityLevel::Unknown,
                    incremental: CapabilityLevel::Unknown,
                },
            ],
        }
    }

    /// 按名称查找 provider 能力。
    pub fn find(&self, provider_id: &str) -> Option<&ProviderCapability> {
        self.providers.iter().find(|p| p.provider_id == provider_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_matrix_has_implemented_providers() {
        let m = ProviderCapabilityMatrix::current();
        assert!(m.providers.len() >= 2);
        assert!(m.find("claude-code").is_some());
        assert!(m.find("codex").is_some());
        assert!(m.find("grok-build").is_some());
    }

    #[test]
    fn implemented_providers_are_experimental() {
        let m = ProviderCapabilityMatrix::current();
        for p in &m.providers {
            // Deferred providers (deepseek-harness/zcode) 保持 Unsupported 无证据，跳过。
            if p.maturity == ProviderMaturity::Unsupported {
                continue;
            }
            assert_eq!(
                p.maturity,
                ProviderMaturity::Experimental,
                "{} 应为 experimental（当前事实，非目标）",
                p.provider_id
            );
        }
    }
    #[test]
    fn target_maturity_is_higher_than_current() {
        let m = ProviderCapabilityMatrix::current();
        for p in &m.providers {
            // Deferred providers (no evidence yet) have no declared target;
            // they stay Unsupported until evidence arrives.
            if p.maturity == ProviderMaturity::Unsupported {
                assert!(
                    ProviderMaturity::target_for(&p.provider_id).is_none(),
                    "{} is unsupported/deferred and must not claim a target",
                    p.provider_id
                );
                continue;
            }
            let target = ProviderMaturity::target_for(&p.provider_id);
            assert!(target.is_some(), "{} should have a target", p.provider_id);
            // Providers whose target IS experimental (cline, aider, zcode, cursor)
            // may have target == current; all others should have target strictly
            // higher than the current experimental maturity.
            if target.unwrap() != ProviderMaturity::Experimental {
                assert_ne!(
                    p.maturity,
                    target.unwrap(),
                    "{} target should differ from current experimental",
                    p.provider_id
                );
            }
        }
    }

    #[test]
    fn unknown_provider_has_no_target() {
        assert!(ProviderMaturity::target_for("nonexistent").is_none());
    }

    #[test]
    fn beta_targets_are_correct() {
        assert_eq!(
            ProviderMaturity::target_for("grok-build"),
            Some(ProviderMaturity::Beta)
        );
        assert_eq!(
            ProviderMaturity::target_for("opencode"),
            Some(ProviderMaturity::Beta)
        );
    }

    #[test]
    fn experimental_targets_are_correct() {
        for id in &["aider", "cline", "cursor"] {
            assert_eq!(
                ProviderMaturity::target_for(id),
                Some(ProviderMaturity::Experimental)
            );
        }
        // zcode 无证据 deferred，与 deepseek-harness 一致：不声明目标
        assert!(ProviderMaturity::target_for("zcode").is_none());
    }

    #[test]
    fn current_matrix_has_all_sixteen_providers() {
        let m = ProviderCapabilityMatrix::current();
        assert_eq!(
            m.providers.len(),
            16,
            "matrix must list all 16 providers, got {}",
            m.providers.len()
        );
    }

    #[test]
    fn search_filters_cover_implemented_matrix_rows_and_preserve_aliases() {
        let values = search_provider_filter_values();
        let matrix = ProviderCapabilityMatrix::current();
        let mut accepted = 0;
        for provider in &matrix.providers {
            let parsed = crate::SearchProvider::parse(&provider.provider_id);
            if provider.maturity == ProviderMaturity::Unsupported {
                assert!(parsed.is_none(), "{}", provider.provider_id);
                assert!(!values.contains(&provider.provider_id.as_str()));
            } else {
                assert_eq!(parsed.unwrap().as_str(), provider.provider_id);
                assert!(values.contains(&provider.provider_id.as_str()));
                accepted += 1;
            }
        }
        assert_eq!(accepted, 14);
        assert_eq!(
            crate::SearchProvider::parse("claude"),
            Some(crate::SearchProvider::Claude)
        );
        assert_eq!(
            crate::SearchProvider::parse("codex"),
            Some(crate::SearchProvider::Codex)
        );
        assert!(crate::SearchProvider::parse("unknown-provider").is_none());
    }

    #[test]
    fn usage_capability_levels_match_the_extraction_slice() {
        let m = ProviderCapabilityMatrix::current();
        // claude-code：assistant 记录自带 message.usage（provider 原生逐消息）。
        assert_eq!(
            m.find("claude-code").unwrap().usage,
            CapabilityLevel::Native
        );
        // codex：token_count 累计量经单调校验转为增量（Derived）。
        assert_eq!(m.find("codex").unwrap().usage, CapabilityLevel::Derived);
        // 其余 12 个已实现 provider：本切片不宣称 usage 能力（诚实不宣传；
        // 格式有无用量事实见各行的注释证据）。
        for id in [
            "aider",
            "grok-build",
            "antigravity",
            "opencode",
            "pi",
            "hermes",
            "cursor",
            "kimi-code",
            "openclaw",
            "qoder",
            "tencent-codebuddy",
            "cline",
        ] {
            assert_eq!(
                m.find(id).unwrap().usage,
                CapabilityLevel::Unsupported,
                "{id}"
            );
        }
        // deferred：未评估。
        for id in ["deepseek-harness", "zcode"] {
            assert_eq!(m.find(id).unwrap().usage, CapabilityLevel::Unknown, "{id}");
        }
    }

    #[test]
    fn deepseek_harness_and_zcode_are_deferred() {
        let m = ProviderCapabilityMatrix::current();
        for id in &["deepseek-harness", "zcode"] {
            let p = m
                .find(id)
                .unwrap_or_else(|| panic!("{id} should be in matrix"));
            assert_eq!(
                p.maturity,
                ProviderMaturity::Unsupported,
                "{id} must remain unsupported/deferred until real transcript evidence exists"
            );
            assert!(
                p.variant_id.is_empty(),
                "{id} variant must be empty when deferred, got {}",
                p.variant_id
            );
        }
    }

    #[test]
    fn hermes_antigravity_cursor_are_experimental() {
        let m = ProviderCapabilityMatrix::current();
        for id in &["hermes", "antigravity", "cursor"] {
            let p = m
                .find(id)
                .unwrap_or_else(|| panic!("{id} should be in matrix"));
            assert_eq!(
                p.maturity,
                ProviderMaturity::Experimental,
                "{id} should be experimental"
            );
            assert!(
                !p.variant_id.is_empty(),
                "{id} should have a variant id once implemented"
            );
        }
    }

    #[test]
    fn matrix_serializes_to_json() {
        let m = ProviderCapabilityMatrix::current();
        let json = serde_json::to_string(&m).unwrap();
        assert!(json.contains("claude-code"));
        assert!(json.contains("grok-build"));
        assert!(json.contains("experimental"));
        let back: ProviderCapabilityMatrix = serde_json::from_str(&json).unwrap();
        assert_eq!(back.providers.len(), m.providers.len());
    }

    #[test]
    fn maturity_as_str_round_trips() {
        for &m in &[
            ProviderMaturity::Experimental,
            ProviderMaturity::Beta,
            ProviderMaturity::Ga,
            ProviderMaturity::Certified,
            ProviderMaturity::Unsupported,
        ] {
            let s = m.as_str();
            let json = serde_json::to_string(&m).unwrap();
            assert!(json.contains(s), "{json} should contain {s}");
        }
    }
}
