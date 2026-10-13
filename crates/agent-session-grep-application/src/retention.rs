//! Message FTS 正文保留策略（借鉴清单 #3：ctx 文本保留策略分级）。
//!
//! ctx（`ctx-history-capture/src/lib.rs` `PROVIDER_MAX_TEXT_CHARS`）把 Message
//! 正文的检索投影截断到 16 000 字符，使 FTS 索引体积从"最坏单条记录大小"
//! 压到固定上界。AgentSessions 采取同一上限，但只约束 **FTS 投影**：catalog
//! payload 保留 provider 原文全文（THREAT-MODEL §6 已裁定"Catalog 不在索引期
//! 改写原文"，get-message 也依赖全文回显）。
//!
//! 因此同一截断必须施加在三个位置，任何一处缺失都会产生真实缺陷：
//!
//! 1. 索引写入侧（adapters-sqlite 的 fts 写入路径）——索引侧强制上限；
//! 2. 按 payload 重投影侧（adapters-sqlite `searchable_text`，rebuild / merge /
//!    put 共用）——否则重建与合并会重新索引全文，投影与写入侧分叉；
//! 3. 入口侧（cli 构造 `(id, payload, text)` 三元组的 text 元素）——current
//!    判定按同一 text 比较，入口不截断会令每条超限消息在每次重同步都被判
//!    not-current，generation 反复推进（幂等重同步失效）。

/// Message 正文 FTS 投影的字符上限（借鉴清单 #3：ctx `PROVIDER_MAX_TEXT_CHARS`
/// = 16 000）。
pub const MESSAGE_FTS_MAX_CHARS: usize = 16_000;

/// 把消息正文截断到 [`MESSAGE_FTS_MAX_CHARS`] 字符，char 边界截断——
/// 绝不在多字节 UTF-8 序列中间切断。不超过上限时原样返回。
pub fn bounded_index_text(text: &str) -> String {
    if text.chars().count() <= MESSAGE_FTS_MAX_CHARS {
        return text.to_string();
    }
    text.chars().take(MESSAGE_FTS_MAX_CHARS).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_index_text_passes_short_and_empty_text_through_unchanged() {
        assert_eq!(bounded_index_text("hello world"), "hello world");
        assert_eq!(bounded_index_text(""), "");
    }

    #[test]
    fn bounded_index_text_keeps_exactly_cap_chars() {
        let text = "x".repeat(MESSAGE_FTS_MAX_CHARS);
        assert_eq!(bounded_index_text(&text), text);
        assert_eq!(
            bounded_index_text(&text).chars().count(),
            MESSAGE_FTS_MAX_CHARS
        );
    }

    #[test]
    fn bounded_index_text_truncates_beyond_cap_by_one_char() {
        let text = "x".repeat(MESSAGE_FTS_MAX_CHARS + 1);
        let bounded = bounded_index_text(&text);
        assert_eq!(bounded.chars().count(), MESSAGE_FTS_MAX_CHARS);
        assert_ne!(bounded, text, "超限必须截断，不得原样返回");
    }

    #[test]
    fn bounded_index_text_never_splits_a_multibyte_char_at_the_cap() {
        // 上限边界恰好落在一个多字节字符中间：必须截断到该字符之前，
        // 产出合法 UTF-8 且恰为 cap 个字符。
        let mut text = "界".repeat(MESSAGE_FTS_MAX_CHARS);
        text.push('超'); // 第 16001 个字符，应被整体丢弃
        let bounded = bounded_index_text(&text);
        assert_eq!(bounded.chars().count(), MESSAGE_FTS_MAX_CHARS);
        assert!(bounded.ends_with('界'));
        assert!(bounded.is_char_boundary(bounded.len()));
    }

    #[test]
    fn bounded_index_text_mixed_ascii_cjk_truncates_at_cap_chars_not_bytes() {
        // 上限按字符数计（与 ctx limit_chars 同义），不是字节数：CJK 正文
        // 截断后仍可达 cap 个字符，尽管字节数远超 cap。
        let text = "搜".repeat(MESSAGE_FTS_MAX_CHARS + 100);
        let bounded = bounded_index_text(&text);
        assert_eq!(bounded.chars().count(), MESSAGE_FTS_MAX_CHARS);
        assert_eq!(bounded.len(), MESSAGE_FTS_MAX_CHARS * 3);
    }
}
