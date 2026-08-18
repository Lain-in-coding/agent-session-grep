//! ResponseBudget：响应预算与结构化截断（CONTRACT-cli-robot-mcp-draft §3）。
//!
//! `max_response_bytes` 是最终序列化字节的硬门；**先排序、后截断**是调用方义务，
//! [`clamp_items`] 只按传入顺序做贪心裁剪。envelope / error / generation 的字节开销
//! 由调用方预留（把 `max_response_bytes` 减去 envelope 估算后再调 [`clamp_items`]）。
//! 预算低于下限是校验错误（[`BudgetError::TooSmall`]，上游映射 invalid_request），
//! 而不是输出无效 JSON。

/// 默认预算：字节上限（4 MiB）。宽松档，CLI/robot 前端用 flag 覆盖。
pub const DEFAULT_MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024;
/// 默认预算：条目上限。
pub const DEFAULT_MAX_ITEMS: usize = 1000;
/// 默认预算：单条 snippet 字符上限。
pub const DEFAULT_MAX_SNIPPET_CHARS: usize = 2000;
/// 默认预算：消息条数上限。
pub const DEFAULT_MAX_MESSAGES: usize = 500;
/// 默认预算：evidence span 条数上限。
pub const DEFAULT_MAX_EVIDENCE_SPANS: usize = 1000;

/// 校验下限：字节预算至少容纳 envelope + 1 个典型条目（CONTRACT §3 预算过小即校验错误）。
pub const MIN_RESPONSE_BYTES: usize = 4096;
/// 校验下限：至少允许 1 个条目。
pub const MIN_ITEMS: usize = 1;
/// 校验下限：至少允许 1 个 snippet 字符。
pub const MIN_SNIPPET_CHARS: usize = 1;
/// 校验下限：至少允许 1 条消息。
pub const MIN_MESSAGES: usize = 1;
/// 校验下限：至少允许 1 个 evidence span。
pub const MIN_EVIDENCE_SPANS: usize = 1;

/// 截断原因：条目数被 `max_items` 截住。
pub const TRUNCATION_MAX_ITEMS: &str = "max_items";
/// 截断原因：字节预算被 `max_response_bytes` 截住。
pub const TRUNCATION_MAX_RESPONSE_BYTES: &str = "max_response_bytes";
/// 截断原因：消息条数被 `max_messages` 截住（context 用例）。
pub const TRUNCATION_MAX_MESSAGES: &str = "max_messages";
/// 截断原因：证据条数被 `max_evidence_spans` 截住（context 用例）。
pub const TRUNCATION_MAX_EVIDENCE_SPANS: &str = "max_evidence_spans";

/// 版本化响应预算（CONTRACT §3）：所有入口（CLI/Robot/MCP）共用同一组限额语义。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ResponseBudget {
    /// 最终序列化字节硬门（含 envelope；调用方在裁剪时预留 envelope 开销）。
    pub max_response_bytes: usize,
    /// 列表类结果的条目上限。
    pub max_items: usize,
    /// 单条 snippet 的字符上限。
    pub max_snippet_chars: usize,
    /// context 类结果的消息条数上限。
    pub max_messages: usize,
    /// evidence span 条数上限。
    pub max_evidence_spans: usize,
}

impl Default for ResponseBudget {
    fn default() -> Self {
        Self {
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
            max_items: DEFAULT_MAX_ITEMS,
            max_snippet_chars: DEFAULT_MAX_SNIPPET_CHARS,
            max_messages: DEFAULT_MAX_MESSAGES,
            max_evidence_spans: DEFAULT_MAX_EVIDENCE_SPANS,
        }
    }
}

impl ResponseBudget {
    /// 校验各字段不低于下限；过小的预算无法容纳合法 envelope，直接拒绝。
    pub fn validate(&self) -> Result<(), BudgetError> {
        let checks = [
            (
                "max_response_bytes",
                self.max_response_bytes,
                MIN_RESPONSE_BYTES,
            ),
            ("max_items", self.max_items, MIN_ITEMS),
            (
                "max_snippet_chars",
                self.max_snippet_chars,
                MIN_SNIPPET_CHARS,
            ),
            ("max_messages", self.max_messages, MIN_MESSAGES),
            (
                "max_evidence_spans",
                self.max_evidence_spans,
                MIN_EVIDENCE_SPANS,
            ),
        ];
        for (name, value, floor) in checks {
            if value < floor {
                return Err(BudgetError::TooSmall(format!(
                    "{name} = {value} is below the floor {floor}"
                )));
            }
        }
        Ok(())
    }
}

/// 预算校验错误：上游统一映射为 invalid_request（校验类退出码）。
#[derive(Debug, thiserror::Error)]
pub enum BudgetError {
    /// 某字段低于其校验下限。
    #[error("response budget too small: {0}")]
    TooSmall(String),
}

/// 结构化截断标记（CONTRACT §3）：响应被裁剪时告知调用方原因。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Truncation {
    /// 是否发生了截断。
    pub truncated: bool,
    /// 截断原因（[`TRUNCATION_MAX_ITEMS`] / [`TRUNCATION_MAX_RESPONSE_BYTES`]）；未截断为 `None`。
    pub reason: Option<String>,
}

/// 按预算裁剪条目：先应用 `max_items`，再按传入顺序对 `est` 估算做贪心字节闸。
///
/// 返回 `(保留条目, 截断标记, 已消耗字节估算)`。
///
/// - **排序在先是调用方义务**：本函数保序贪心，不重排；
/// - `max_bytes` 应是扣除 envelope 预留后的净预算（envelope 开销由调用方保留）；
/// - `est` 必须计入条目最终渲染的全部字节——检索命中携带的 snippet 同样受
///   `max_response_bytes` 闸约束（snippet 是渲染产物，不是免费内容）；
/// - 两道闸都触发时 reason 报字节闸——它决定了最终条数，增大 `max_items` 无济于事；
/// - 首条即超字节预算时返回空集（consumed 为 0），由调用方决定如何降级。
pub fn clamp_items<T>(
    items: Vec<T>,
    max_items: usize,
    max_bytes: usize,
    est: impl Fn(&T) -> usize,
) -> (Vec<T>, Truncation, usize) {
    let total = items.len();
    let mut kept = items;
    let mut reason = None;
    if kept.len() > max_items {
        kept.truncate(max_items);
        reason = Some(TRUNCATION_MAX_ITEMS.to_string());
    }
    let mut consumed = 0usize;
    let mut fit = kept.len();
    for (i, item) in kept.iter().enumerate() {
        let cost = est(item);
        if consumed.saturating_add(cost) > max_bytes {
            fit = i;
            reason = Some(TRUNCATION_MAX_RESPONSE_BYTES.to_string());
            break;
        }
        consumed += cost;
    }
    kept.truncate(fit);
    let truncated = kept.len() < total;
    (kept, Truncation { truncated, reason }, consumed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_budget_is_generous_and_valid() {
        let b = ResponseBudget::default();
        assert_eq!(b.max_response_bytes, DEFAULT_MAX_RESPONSE_BYTES);
        assert_eq!(b.max_items, DEFAULT_MAX_ITEMS);
        assert_eq!(b.max_snippet_chars, DEFAULT_MAX_SNIPPET_CHARS);
        assert_eq!(b.max_messages, DEFAULT_MAX_MESSAGES);
        assert_eq!(b.max_evidence_spans, DEFAULT_MAX_EVIDENCE_SPANS);
        b.validate().unwrap();
    }

    #[test]
    fn validate_rejects_each_field_below_floor() {
        let cases = [
            (
                "max_response_bytes",
                ResponseBudget {
                    max_response_bytes: MIN_RESPONSE_BYTES - 1,
                    ..Default::default()
                },
            ),
            (
                "max_items",
                ResponseBudget {
                    max_items: 0,
                    ..Default::default()
                },
            ),
            (
                "max_snippet_chars",
                ResponseBudget {
                    max_snippet_chars: 0,
                    ..Default::default()
                },
            ),
            (
                "max_messages",
                ResponseBudget {
                    max_messages: 0,
                    ..Default::default()
                },
            ),
            (
                "max_evidence_spans",
                ResponseBudget {
                    max_evidence_spans: 0,
                    ..Default::default()
                },
            ),
        ];
        for (field, budget) in cases {
            let BudgetError::TooSmall(msg) = budget.validate().unwrap_err();
            assert!(msg.contains(field), "{field}: {msg}");
        }
    }

    #[test]
    fn validate_accepts_exact_floors() {
        let b = ResponseBudget {
            max_response_bytes: MIN_RESPONSE_BYTES,
            max_items: MIN_ITEMS,
            max_snippet_chars: MIN_SNIPPET_CHARS,
            max_messages: MIN_MESSAGES,
            max_evidence_spans: MIN_EVIDENCE_SPANS,
        };
        b.validate().unwrap();
    }

    #[test]
    fn clamp_is_noop_under_budget() {
        let items = vec!["aa", "bb", "cc"];
        let (kept, trunc, consumed) = clamp_items(items.clone(), 10, 100, |s| s.len());
        assert_eq!(kept, items);
        assert_eq!(
            trunc,
            Truncation {
                truncated: false,
                reason: None
            }
        );
        assert_eq!(consumed, 6);
    }

    #[test]
    fn clamp_cuts_by_max_items_first() {
        let items = vec!["a", "b", "c", "d", "e"];
        let (kept, trunc, consumed) = clamp_items(items, 3, 1000, |s| s.len());
        assert_eq!(kept, vec!["a", "b", "c"]);
        assert!(trunc.truncated);
        assert_eq!(trunc.reason.as_deref(), Some(TRUNCATION_MAX_ITEMS));
        assert_eq!(consumed, 3);
    }

    #[test]
    fn clamp_byte_gate_cuts_greedily_in_order() {
        let items = vec!["aaaaaaaaaa"; 5]; // 每条估算 10 字节
        let (kept, trunc, consumed) = clamp_items(items, 100, 25, |s| s.len());
        assert_eq!(kept.len(), 2);
        assert!(trunc.truncated);
        assert_eq!(trunc.reason.as_deref(), Some(TRUNCATION_MAX_RESPONSE_BYTES));
        assert_eq!(consumed, 20);
    }

    #[test]
    fn clamp_reports_byte_gate_when_both_cut() {
        let items = vec!["aaaaaaaaaa"; 10];
        let (kept, trunc, consumed) = clamp_items(items, 5, 25, |s| s.len());
        assert_eq!(kept.len(), 2);
        assert!(trunc.truncated);
        // 字节闸决定了最终条数，报它而不是 max_items。
        assert_eq!(trunc.reason.as_deref(), Some(TRUNCATION_MAX_RESPONSE_BYTES));
        assert_eq!(consumed, 20);
    }

    #[test]
    fn clamp_returns_empty_when_first_item_exceeds_bytes() {
        let items = vec!["aaaaaaaaaa"];
        let (kept, trunc, consumed) = clamp_items(items, 10, 5, |s| s.len());
        assert!(kept.is_empty());
        assert!(trunc.truncated);
        assert_eq!(trunc.reason.as_deref(), Some(TRUNCATION_MAX_RESPONSE_BYTES));
        assert_eq!(consumed, 0);
    }

    #[test]
    fn clamp_exact_byte_fit_is_not_truncated() {
        let items = vec!["aaaaa", "bbbbb"]; // 恰好 10 字节
        let (kept, trunc, consumed) = clamp_items(items, 10, 10, |s| s.len());
        assert_eq!(kept.len(), 2);
        assert!(!trunc.truncated);
        assert_eq!(trunc.reason, None);
        assert_eq!(consumed, 10);
    }

    #[test]
    fn clamp_charges_snippet_bytes_toward_byte_gate() {
        // R1.2 约定：est 必须计入 snippet 字节（snippet 是渲染产物，不是免费内容）。
        // est = id(10) + snippet 序列化字节 + `,"text":` 字段开销(8)。
        // 预算 130 只容 1 条带 100 字符 snippet 的命中；截断原因显式报字节闸。
        let items = vec!["a".repeat(100), "b".repeat(100), "c".repeat(100)];
        let (kept, trunc, consumed) = clamp_items(items, 10, 130, |s: &String| 10 + s.len() + 8);
        assert_eq!(kept.len(), 1);
        assert!(trunc.truncated);
        assert_eq!(trunc.reason.as_deref(), Some(TRUNCATION_MAX_RESPONSE_BYTES));
        assert_eq!(consumed, 118);
    }

    #[test]
    fn truncation_serializes_with_snake_case_fields() {
        let t = Truncation {
            truncated: true,
            reason: Some(TRUNCATION_MAX_ITEMS.to_string()),
        };
        let json = serde_json::to_string(&t).unwrap();
        assert_eq!(json, r#"{"truncated":true,"reason":"max_items"}"#);
        let back: Truncation = serde_json::from_str(&json).unwrap();
        assert_eq!(back, t);
    }

    #[test]
    fn budget_serde_round_trip() {
        let b = ResponseBudget::default();
        let json = serde_json::to_string(&b).unwrap();
        assert!(json.contains("\"max_response_bytes\""), "{json}");
        let back: ResponseBudget = serde_json::from_str(&json).unwrap();
        assert_eq!(back, b);
    }
}
