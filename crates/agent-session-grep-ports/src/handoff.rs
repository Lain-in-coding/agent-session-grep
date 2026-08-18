//! Handoff Pack v1 契约类型（handoff-pack/v1）。
//!
//! JSON 是权威结构；Markdown 是 deterministic projection。
//! evidence（原文证据）与 inference（推断摘要）严格分栏，不混写。
//! 实现落在 `08-15-evidence-handoff-pack` 子任务；本模块只定义契约类型。
//!
//! `RetrievalMode`、`RedactionStatus`、`RedactionMode`、`RedactionState`
//! 定义在 crate root（`lib.rs`），本模块 re-export 以保持 handoff 契约自洽。

pub use crate::{RedactionMode, RedactionState, RedactionStatus, RetrievalMode};

/// Handoff pack v1 权威结构。JSON 序列化为 `schemas/handoff/v1/pack.schema.json`。
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct HandoffPack {
    pub schema_version: String,
    pub pack_id: String,
    pub catalog_generation: u64,
    /// 生成方式：当前恒为 `Deterministic`（PRD Q44 默认不调用任何模型）。
    pub generation_mode: GenerationMode,
    pub query: HandoffQuery,
    /// 确定性时间戳：由 pinned catalog generation 派生（固定 base + generation），
    /// 同 generation/query/budget 下字节可复现。
    pub created_at: String,
    pub matched_sessions: Vec<MatchedSession>,
    pub mainline: Vec<MainlineEntry>,
    pub evidence: Vec<EvidenceEntry>,
    pub inference: Vec<InferenceEntry>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<HandoffTarget>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time_window: Option<TimeWindow>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provenance: Option<Provenance>,
    pub budget: HandoffBudget,
    pub truncation: TruncationStatus,
    pub redaction: RedactionStatus,
    pub confidence: PackConfidence,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tool_activity: Vec<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub source_locators: Vec<SourceLocator>,
}

impl HandoffPack {
    pub const SCHEMA_VERSION: &'static str = "1.0";
}

/// 生成方式：deterministic（默认，不调用模型）或 local LLM（显式 opt-in）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GenerationMode {
    Deterministic,
    LocalLlm,
}

/// 查询应用的时间窗（半开区间 `[since, until)`，与 filters 的 since/until 对齐）。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TimeWindow {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub since: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub until: Option<String>,
}

/// Pack 的出处：目标 provider/session。搜索型 pack 无单一会话/提供商时保持
/// `None`（honest，绝不臆造）；会话型 handoff 由后续 slice 填充。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Provenance {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct HandoffQuery {
    pub terms: Vec<String>,
    pub retrieval_mode: RetrievalMode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filters: Option<HandoffFilters>,
}

#[derive(Debug, Clone, Default, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct HandoffFilters {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub providers: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub since: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub until: Option<String>,
}

/// 声明目标 provider/agent。asg 只输出 pack 与建议命令，不静默注入。
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct HandoffTarget {
    pub provider_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suggested_command: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct MatchedSession {
    pub session_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    pub relevance_score: f64,
    pub occurrences: u64,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct MainlineEntry {
    pub message_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    pub role: String,
    pub ordinal: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text_preview: Option<String>,
    #[serde(default)]
    pub is_sidechain: bool,
}

/// 原文证据：来自 Catalog 的 source span，不混入推断。
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct EvidenceEntry {
    pub message_id: String,
    pub source_document_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub span_start: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub span_end: Option<u64>,
    pub text: String,
}

/// 推断摘要：local LLM 或 deterministic 派生，永远标记 inference。
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct InferenceEntry {
    pub kind: InferenceKind,
    pub text: String,
    pub source: InferenceSource,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model_id: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InferenceKind {
    Summary,
    Decision,
    Risk,
    Recommendation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InferenceSource {
    /// 用户显式启用的本地 LLM 摘要。
    LocalLlm,
    /// 默认确定性生成（不调用模型）。
    Deterministic,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct SourceLocator {
    pub source_document_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct HandoffBudget {
    pub max_tokens: u64,
    pub max_bytes: u64,
    pub used_tokens: u64,
    pub used_bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_evidence: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context_lines: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct TruncationStatus {
    pub truncated: bool,
    pub reason: TruncationReason,
    #[serde(default)]
    pub dropped_count: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dropped_locators: Vec<SourceLocator>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TruncationReason {
    BudgetExceeded,
    MaxItems,
    MaxEvidence,
    MaxBytes,
    None,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct PackConfidence {
    pub overall: ConfidenceLevel,
    pub per_session: Vec<SessionConfidence>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfidenceLevel {
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct SessionConfidence {
    pub session_id: String,
    pub confidence: ConfidenceLevel,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retrieval_mode_serializes_snake_case() {
        assert_eq!(
            serde_json::to_string(&RetrievalMode::LexicalFallback).unwrap(),
            "\"lexical_fallback\""
        );
        assert_eq!(
            serde_json::to_string(&RetrievalMode::Hybrid).unwrap(),
            "\"hybrid\""
        );
    }

    #[test]
    fn redaction_default_is_none_redacted() {
        let r = RedactionStatus::default();
        assert_eq!(r.mode, RedactionMode::Default);
        assert_eq!(r.status, RedactionState::None);
        assert_eq!(r.redacted_count, 0);
        assert!(r.audit_id.is_none());
    }

    #[test]
    fn redaction_round_trip_preserves_revealed_audit() {
        let r = RedactionStatus {
            mode: RedactionMode::Revealed,
            status: RedactionState::Applied,
            ruleset_version: "v1.0".into(),
            redacted_count: 3,
            audit_id: Some("audit-xyz".into()),
        };
        let json = serde_json::to_string(&r).unwrap();
        let back: RedactionStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(back, r);
    }

    #[test]
    fn evidence_and_inference_types_are_distinct() {
        // 编译期保证：evidence 和 inference 是不同类型，不能混写。
        let _evidence: Vec<EvidenceEntry> = Vec::new();
        let _inference: Vec<InferenceEntry> = Vec::new();
    }
}
