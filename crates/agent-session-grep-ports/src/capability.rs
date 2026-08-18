//! Provider Capability Matrix（能力矩阵单源权威）。
//!
//! 所有入口（CLI/MCP/Robot/Web）渲染 provider 能力必须读本矩阵，禁止硬编码。
//! 当前已实现的 provider maturity=experimental，在 `08-15-sixteen-provider-evidence-wave`
//! 任务中逐步实现并晋级。
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
    /// Handoff 能力。
    pub handoff: CapabilityLevel,
    /// 工具活动提取能力。
    pub tool_activity: CapabilityLevel,
    /// Source span 精度。
    pub source_span: CapabilityLevel,
    /// 增量同步能力。
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

impl ProviderCapabilityMatrix {
    /// 返回当前 16 个 provider 的能力矩阵（evidence wave 08-15 全量：
    /// 14 个已实现 + 2 个 deferred）。deferred provider（deepseek-harness/zcode）
    /// 无 transcript 证据，保持 Unsupported 不宣传。
    pub fn current() -> Self {
        Self {
            providers: vec![
                ProviderCapability {
                    provider_id: "aider".into(),
                    variant_id: "aider/chat-history-md-v1".into(),
                    maturity: ProviderMaturity::Experimental,
                    discover: CapabilityLevel::Unsupported,
                    probe: CapabilityLevel::Native,
                    parse: CapabilityLevel::Native,
                    search: CapabilityLevel::Native,
                    context: CapabilityLevel::Unsupported,
                    resume: CapabilityLevel::Unsupported,
                    handoff: CapabilityLevel::Unsupported,
                    tool_activity: CapabilityLevel::Partial,
                    source_span: CapabilityLevel::Derived,
                    incremental: CapabilityLevel::Unsupported,
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
                    handoff: CapabilityLevel::Unsupported,
                    tool_activity: CapabilityLevel::Partial,
                    source_span: CapabilityLevel::Native,
                    incremental: CapabilityLevel::Native,
                },
                ProviderCapability {
                    provider_id: "codex".into(),
                    variant_id: "codex/rollout-jsonl-v1".into(),
                    maturity: ProviderMaturity::Experimental,
                    discover: CapabilityLevel::Native,
                    probe: CapabilityLevel::Native,
                    parse: CapabilityLevel::Native,
                    search: CapabilityLevel::Native,
                    context: CapabilityLevel::Native,
                    resume: CapabilityLevel::Derived,
                    handoff: CapabilityLevel::Unsupported,
                    tool_activity: CapabilityLevel::Partial,
                    source_span: CapabilityLevel::Native,
                    incremental: CapabilityLevel::Native,
                },
                ProviderCapability {
                    provider_id: "grok-build".into(),
                    variant_id: "grok-build/acp-updates-v1".into(),
                    maturity: ProviderMaturity::Experimental,
                    discover: CapabilityLevel::Unsupported,
                    probe: CapabilityLevel::Native,
                    parse: CapabilityLevel::Native,
                    search: CapabilityLevel::Native,
                    context: CapabilityLevel::Unsupported,
                    // resume 命令已由 application::resume builder 支持（grok --resume），
                    // 与矩阵一致标记 Derived（audit P1-2 drift 测试守护）。
                    resume: CapabilityLevel::Derived,
                    handoff: CapabilityLevel::Unsupported,
                    tool_activity: CapabilityLevel::Unsupported,
                    source_span: CapabilityLevel::Native,
                    incremental: CapabilityLevel::Unsupported,
                },
                ProviderCapability {
                    provider_id: "pi".into(),
                    variant_id: "pi/session-jsonl-v1".into(),
                    maturity: ProviderMaturity::Experimental,
                    discover: CapabilityLevel::Unsupported,
                    probe: CapabilityLevel::Native,
                    parse: CapabilityLevel::Native,
                    search: CapabilityLevel::Native,
                    context: CapabilityLevel::Unsupported,
                    resume: CapabilityLevel::Derived,
                    handoff: CapabilityLevel::Unsupported,
                    tool_activity: CapabilityLevel::Unsupported,
                    source_span: CapabilityLevel::Native,
                    incremental: CapabilityLevel::Unsupported,
                },
                ProviderCapability {
                    provider_id: "kimi-code".into(),
                    variant_id: "kimi-code/wire-jsonl-v1".into(),
                    maturity: ProviderMaturity::Experimental,
                    discover: CapabilityLevel::Unsupported,
                    probe: CapabilityLevel::Native,
                    parse: CapabilityLevel::Native,
                    search: CapabilityLevel::Native,
                    context: CapabilityLevel::Unsupported,
                    resume: CapabilityLevel::Unknown,
                    handoff: CapabilityLevel::Unsupported,
                    tool_activity: CapabilityLevel::Unsupported,
                    source_span: CapabilityLevel::Native,
                    incremental: CapabilityLevel::Unsupported,
                },
                ProviderCapability {
                    provider_id: "qoder".into(),
                    variant_id: "qoder/transcript-jsonl-v1".into(),
                    maturity: ProviderMaturity::Experimental,
                    discover: CapabilityLevel::Unsupported,
                    probe: CapabilityLevel::Native,
                    parse: CapabilityLevel::Native,
                    search: CapabilityLevel::Native,
                    context: CapabilityLevel::Unsupported,
                    resume: CapabilityLevel::Unknown,
                    handoff: CapabilityLevel::Unsupported,
                    tool_activity: CapabilityLevel::Unsupported,
                    source_span: CapabilityLevel::Native,
                    incremental: CapabilityLevel::Unsupported,
                },
                ProviderCapability {
                    provider_id: "openclaw".into(),
                    variant_id: "openclaw/session-jsonl-v3".into(),
                    maturity: ProviderMaturity::Experimental,
                    discover: CapabilityLevel::Unsupported,
                    probe: CapabilityLevel::Native,
                    parse: CapabilityLevel::Native,
                    search: CapabilityLevel::Native,
                    context: CapabilityLevel::Unsupported,
                    resume: CapabilityLevel::Unsupported,
                    handoff: CapabilityLevel::Unsupported,
                    tool_activity: CapabilityLevel::Unsupported,
                    source_span: CapabilityLevel::Native,
                    incremental: CapabilityLevel::Unsupported,
                },
                ProviderCapability {
                    provider_id: "tencent-codebuddy".into(),
                    variant_id: "tencent-codebuddy/cli-jsonl-v1".into(),
                    maturity: ProviderMaturity::Experimental,
                    discover: CapabilityLevel::Unsupported,
                    probe: CapabilityLevel::Native,
                    parse: CapabilityLevel::Native,
                    search: CapabilityLevel::Native,
                    context: CapabilityLevel::Unsupported,
                    resume: CapabilityLevel::Unknown,
                    handoff: CapabilityLevel::Unsupported,
                    tool_activity: CapabilityLevel::Unsupported,
                    source_span: CapabilityLevel::Native,
                    incremental: CapabilityLevel::Unsupported,
                },
                ProviderCapability {
                    provider_id: "opencode".into(),
                    variant_id: "opencode/sqlite-v1".into(),
                    maturity: ProviderMaturity::Experimental,
                    discover: CapabilityLevel::Unsupported,
                    probe: CapabilityLevel::Native,
                    parse: CapabilityLevel::Native,
                    search: CapabilityLevel::Native,
                    context: CapabilityLevel::Unsupported,
                    // resume 命令尚无权威模板（builder 未支持），如实标记 Unknown——
                    // 曾误标 Derived（audit P1-2 drift 测试守护）。
                    resume: CapabilityLevel::Unknown,
                    handoff: CapabilityLevel::Unsupported,
                    tool_activity: CapabilityLevel::Unsupported,
                    source_span: CapabilityLevel::Unsupported,
                    incremental: CapabilityLevel::Unsupported,
                },
                ProviderCapability {
                    provider_id: "cline".into(),
                    variant_id: "cline/api-conversation-history-v1".into(),
                    maturity: ProviderMaturity::Experimental,
                    discover: CapabilityLevel::Unsupported,
                    probe: CapabilityLevel::Native,
                    parse: CapabilityLevel::Native,
                    search: CapabilityLevel::Native,
                    context: CapabilityLevel::Unsupported,
                    resume: CapabilityLevel::Unsupported,
                    handoff: CapabilityLevel::Unsupported,
                    tool_activity: CapabilityLevel::Unsupported,
                    source_span: CapabilityLevel::Unsupported,
                    incremental: CapabilityLevel::Unsupported,
                },
                ProviderCapability {
                    provider_id: "hermes".into(),
                    variant_id: "hermes/session-json-v1".into(),
                    maturity: ProviderMaturity::Experimental,
                    discover: CapabilityLevel::Unsupported,
                    probe: CapabilityLevel::Native,
                    parse: CapabilityLevel::Native,
                    search: CapabilityLevel::Native,
                    context: CapabilityLevel::Unsupported,
                    resume: CapabilityLevel::Unknown,
                    handoff: CapabilityLevel::Unsupported,
                    tool_activity: CapabilityLevel::Unsupported,
                    source_span: CapabilityLevel::Unsupported,
                    incremental: CapabilityLevel::Unsupported,
                },
                ProviderCapability {
                    provider_id: "antigravity".into(),
                    variant_id: "antigravity/transcript-jsonl-v1".into(),
                    maturity: ProviderMaturity::Experimental,
                    discover: CapabilityLevel::Unsupported,
                    probe: CapabilityLevel::Native,
                    parse: CapabilityLevel::Native,
                    search: CapabilityLevel::Native,
                    context: CapabilityLevel::Unsupported,
                    resume: CapabilityLevel::Unknown,
                    handoff: CapabilityLevel::Unsupported,
                    tool_activity: CapabilityLevel::Unsupported,
                    source_span: CapabilityLevel::Unsupported,
                    incremental: CapabilityLevel::Unsupported,
                },
                ProviderCapability {
                    provider_id: "cursor".into(),
                    variant_id: "cursor/vscdb-chat-v1".into(),
                    maturity: ProviderMaturity::Experimental,
                    discover: CapabilityLevel::Unsupported,
                    probe: CapabilityLevel::Native,
                    parse: CapabilityLevel::Native,
                    search: CapabilityLevel::Native,
                    context: CapabilityLevel::Unsupported,
                    resume: CapabilityLevel::Unknown,
                    handoff: CapabilityLevel::Unsupported,
                    tool_activity: CapabilityLevel::Unsupported,
                    source_span: CapabilityLevel::Unsupported,
                    incremental: CapabilityLevel::Unsupported,
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
            "matrix must list all 16 providers (evidence wave 08-15), got {}",
            m.providers.len()
        );
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
                "{id} should be experimental (evidence wave 08-16)"
            );
            assert!(
                !p.variant_id.is_empty(),
                "{id} should have a variant id after evidence-wave implementation"
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
