//! 领域错误：CLI exit code 与协议错误映射见 CLI/Robot/MCP contract 和
//! `schemas/robot/v1/error-catalog.json`。
//!
//! Domain 层只定义"发生了什么"，不决定 CLI exit code 或 MCP code——
//! 那是 protocol 层的映射职责（见 docs/contracts/CONTRACT-cli-robot-mcp-draft.md）。

use thiserror::Error;

/// 领域层错误。稳定的 `code()` 供上层做协议映射，不直接暴露内部细节。
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum DomainError {
    /// 请求引用的对象不存在。
    #[error("not found: {0}")]
    NotFound(String),

    /// 参数或请求校验失败。
    #[error("invalid request: {0}")]
    InvalidRequest(String),

    /// 违反领域不变量（这是 bug 信号，不应对最终用户暴露细节）。
    #[error("invariant violation: {0}")]
    InvariantViolation(String),

    /// 身份稳定性不足，无法按 native 等级承诺（见 RFC-0001）。
    #[error("unstable identity: {0}")]
    UnstableIdentity(String),

    /// 会话内的上下文关系无法唯一解析，不能替调用方猜测分支。
    #[error("ambiguous graph: {0}")]
    AmbiguousGraph(String),
}

impl DomainError {
    /// 稳定错误码，供 protocol 层映射到 exit code / MCP code。
    /// 该字符串是对外契约的一部分，不可随意更名。
    pub fn code(&self) -> &'static str {
        match self {
            DomainError::NotFound(_) => "not_found",
            DomainError::InvalidRequest(_) => "invalid_request",
            DomainError::InvariantViolation(_) => "invariant_violation",
            DomainError::UnstableIdentity(_) => "unstable_identity",
            DomainError::AmbiguousGraph(_) => "ambiguous_graph",
        }
    }
}

pub type DomainResult<T> = Result<T, DomainError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn code_is_stable() {
        assert_eq!(DomainError::NotFound("x".into()).code(), "not_found");
        assert_eq!(
            DomainError::InvalidRequest("x".into()).code(),
            "invalid_request"
        );
        assert_eq!(
            DomainError::InvariantViolation("x".into()).code(),
            "invariant_violation"
        );
        assert_eq!(
            DomainError::UnstableIdentity("x".into()).code(),
            "unstable_identity"
        );
        assert_eq!(
            DomainError::AmbiguousGraph("x".into()).code(),
            "ambiguous_graph"
        );
    }
}
