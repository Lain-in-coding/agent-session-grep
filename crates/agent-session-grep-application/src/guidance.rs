//! Search match guidance: deterministic literal-match evidence and bounded
//! next-call suggestions. These additive machine-facing fields do not affect
//! scoring, ordering, cursors, or human rendering.

use agent_session_grep_ports::SearchHit;

use crate::bigram_cjk;

/// Maximum literal evidence entries attached to one search hit.
pub const MAX_WHY_MATCHED: usize = 8;
/// Maximum suggested next calls attached to one search hit.
pub const MAX_SUGGESTED_COMMANDS: usize = 2;
/// Small bounded context window used by the preferred message lookup.
pub const SUGGESTED_AROUND: u32 = 2;

fn is_evidence_term(term: &str) -> bool {
    !term.is_empty() && term.chars().any(char::is_alphanumeric)
}

/// Derive bounded, de-duplicated literal terms using the same CJK/plain-text
/// transform as search indexing. FTS quoting remains an adapter-private detail.
pub fn literal_terms(query: &str) -> Vec<String> {
    let mut terms = Vec::new();
    for term in bigram_cjk(query).split_whitespace() {
        if !is_evidence_term(term) || terms.iter().any(|seen| seen == term) {
            continue;
        }
        terms.push(term.to_string());
        if terms.len() >= MAX_WHY_MATCHED {
            break;
        }
    }
    terms
}

/// Return query terms that occur in the complete, untruncated hit text, in
/// query order. No regex, classifier, LLM, or FTS syntax is involved.
///
/// Text is drawn from these places, in order, all bounded by the full catalog
/// payload:
/// 1. The canonical `text` string field;
/// 2. plain-white-space-joined string fields (e.g. Codex content blocks where
///    the JSON payload keeps no top-level `text`);
/// 3. all string leaf values beneath the payload (non-string leaves and the
///    two id fields are skipped so evidence never mixes payload with identity);
/// 4. the hit's own display prefix when the payload is opaque binary.
///
/// The 4th fallback is deliberately order-last because a display prefix may be
/// a *snippet* that omits a later true match.
pub fn why_matched(
    query_terms: &[String],
    full_text: Option<&str>,
    payload_text: Option<&str>,
    payload: Option<&serde_json::Value>,
    display_prefix: Option<&str>,
) -> Vec<String> {
    for haystack in [
        full_text,
        payload_text,
        payload.and_then(string_leaves_concat).as_deref(),
        display_prefix,
    ]
    .into_iter()
    .flatten()
    {
        let found = why_matched_in(&bigram_cjk(haystack), query_terms);
        if !found.is_empty() {
            return found;
        }
    }
    Vec::new()
}

/// Deterministic containment of query terms in a pre-transformed haystack.
fn why_matched_in(haystack_bigram: &str, query_terms: &[String]) -> Vec<String> {
    let lower = haystack_bigram.to_lowercase();
    query_terms
        .iter()
        .filter(|term| lower.contains(&term.to_lowercase()))
        .cloned()
        .collect()
}

/// Deterministically concatenated searchable string leaves of a catalog
/// payload, JSON-serialized, in stable key order. Payloads that are not JSON
/// objects yield `None` and skip this evidence source.
fn string_leaves_concat(payload: &serde_json::Value) -> Option<String> {
    let mut leaves = Vec::new();
    collect_string_leaves(payload, &mut leaves);
    if leaves.is_empty() {
        return None;
    }
    Some(leaves.join("\n"))
}

fn collect_string_leaves(value: &serde_json::Value, out: &mut Vec<String>) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, child) in map {
                if key == "id" || key == "session_id" {
                    continue;
                }
                collect_string_leaves(child, out);
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                collect_string_leaves(item, out);
            }
        }
        serde_json::Value::String(text) => out.push(text.clone()),
        _ => {}
    }
}

/// POSIX 单引号包裹：参数含 shell 元字符或空白时用 `'...'` 包裹、内嵌单引号按
/// `'\''` 转义；仅由字母/数字/`_./-` 构成的安全参数原样返回。这样既保证建议
/// 命令可直接粘贴进 shell，又不改变常见安全 wire id 的既有输出字节。
///
/// 改编自 agf 的 shell quoting（MIT License）。
fn shell_quote_arg(arg: &str) -> String {
    if !arg.is_empty()
        && arg
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'/' | b'-'))
    {
        return arg.to_string();
    }
    let mut out = String::with_capacity(arg.len() + 2);
    out.push('\'');
    for c in arg.chars() {
        if c == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(c);
        }
    }
    out.push('\'');
    out
}

/// Suggest valid next calls only when the hit carries every required real ID.
/// The message lookup is preferred, followed by the session context lookup.
/// Arguments are shell-quoted so ids containing whitespace or metacharacters
/// never produce an ambiguous one-liner.
pub fn suggested_next_commands(hit: &SearchHit) -> Vec<String> {
    let mut commands = Vec::new();
    if let Some(session_id) = hit.session_id.as_deref() {
        commands.push(format!(
            "agent-session-grep get-message {} --session {} --around {SUGGESTED_AROUND}",
            shell_quote_arg(hit.id.as_str()),
            shell_quote_arg(session_id)
        ));
        commands.push(format!(
            "agent-session-grep context {}",
            shell_quote_arg(session_id)
        ));
    }
    commands.truncate(MAX_SUGGESTED_COMMANDS);
    commands
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_session_grep_domain::{IdKind, StableId};

    fn hit(message_id: &str, session_id: Option<&str>) -> SearchHit {
        SearchHit {
            id: StableId::native(IdKind::Message, message_id),
            score: 0.0,
            session_id: session_id.map(str::to_string),
            text: None,
            why_matched: Vec::new(),
            suggested_next_commands: Vec::new(),
            occurrences: 1,
            resume_available: false,
        }
    }

    #[test]
    fn literal_terms_dedupe_in_query_order_and_skip_punctuation() {
        assert_eq!(
            literal_terms("alpha beta alpha : -- beta"),
            vec!["alpha", "beta"]
        );
    }

    #[test]
    fn literal_terms_apply_cjk_bigram_transform() {
        assert_eq!(literal_terms("配置备份"), vec!["配置", "置备", "备份"]);
        assert!(literal_terms("配").is_empty());
        assert_eq!(literal_terms("配置v2.0备份"), vec!["配置", "v2.0", "备份"]);
    }

    #[test]
    fn why_matched_finds_ascii_and_cjk_terms() {
        assert_eq!(
            why_matched(
                &literal_terms("needle"),
                Some("haystack with a needle"),
                None,
                None,
                None
            ),
            vec!["needle"]
        );
        assert_eq!(
            why_matched(
                &literal_terms("数据库"),
                Some("涉及数据库迁移"),
                None,
                None,
                None
            ),
            vec!["数据", "据库"]
        );
    }

    #[test]
    fn why_matched_matches_ascii_case_insensitively() {
        assert_eq!(
            why_matched(
                &literal_terms("NEEDLE"),
                Some("haystack with a needle"),
                None,
                None,
                None
            ),
            vec!["NEEDLE"]
        );
    }

    #[test]
    fn why_matched_detects_match_beyond_displayed_prefix() {
        let mut text = "x".repeat(500);
        text.push_str(" needle");
        assert_eq!(
            why_matched(&literal_terms("needle"), Some(&text), None, None, None),
            vec!["needle"]
        );
    }

    #[test]
    fn why_matched_is_empty_without_text_or_match() {
        let terms = literal_terms("needle");
        assert!(why_matched(&terms, None, None, None, None).is_empty());
        assert!(why_matched(&terms, Some("no such term here"), None, None, None).is_empty());
    }

    #[test]
    fn why_matched_keeps_query_order_and_respects_cap() {
        assert_eq!(
            why_matched(
                &literal_terms("beta alpha"),
                Some("alpha then beta"),
                None,
                None,
                None
            ),
            vec!["beta", "alpha"]
        );
        let query = (0..20)
            .map(|i| format!("t{i}"))
            .collect::<Vec<_>>()
            .join(" ");
        assert_eq!(literal_terms(&query).len(), MAX_WHY_MATCHED);
    }

    #[test]
    fn why_matched_falls_back_to_string_leaves_of_payload() {
        // Codex content blocks keep no top-level `text`; the payload tree's
        // string leaves must still produce evidence (guidance source 3).
        let payload = serde_json::json!({
            "role": "assistant",
            "content": [
                {"type": "text", "text": "涉及数据库迁移的说明"},
                {"type": "tool_use", "name": "search"}
            ]
        });
        let terms = literal_terms("数据库迁移");
        let found = why_matched(&terms, None, None, Some(&payload), None);
        assert_eq!(found, vec!["数据", "据库", "库迁", "迁移"]);
    }

    #[test]
    fn why_matched_prefers_primary_text_over_payload_leaves() {
        // Canonical `text` is source 1 and wins even when the payload leaves
        // also contain the term.
        let payload = serde_json::json!({"role": "user", "content": "leaf needle"});
        let terms = literal_terms("needle");
        assert_eq!(
            why_matched(&terms, Some("primary needle"), None, Some(&payload), None),
            vec!["needle"]
        );
    }

    #[test]
    fn why_matched_uses_display_prefix_as_last_resort() {
        // Opaque (non-JSON) payloads have neither text nor parseable leaves;
        // the display prefix is the only remaining evidence source.
        let terms = literal_terms("needle");
        assert_eq!(
            why_matched(&terms, None, None, None, Some("display prefix with needle")),
            vec!["needle"]
        );
        // ... and it stays last: a parseable payload beats the prefix.
        let payload = serde_json::json!({"role": "user", "content": "leaf needle"});
        assert_eq!(
            why_matched(&terms, None, None, Some(&payload), Some("display prefix")),
            vec!["needle"]
        );
    }

    #[test]
    fn suggestions_use_real_ids_and_are_bounded() {
        let commands = suggested_next_commands(&hit("msg-1", Some("ses-1")));
        assert_eq!(commands.len(), 2);
        assert!(commands[0].contains("msg-1"));
        assert!(commands[0].contains("ses-1"));
        assert!(commands[0].contains("--around 2"));
        assert!(commands[1].contains("context ses-1"));
        assert!(commands.len() <= MAX_SUGGESTED_COMMANDS);
    }

    #[test]
    fn suggestions_are_omitted_without_session_id() {
        assert!(suggested_next_commands(&hit("msg-1", None)).is_empty());
    }

    #[test]
    fn suggestions_shell_quote_unsafe_arguments_only() {
        // 安全 wire id 原样输出（既有字节不变）；含空白/元字符的 id 用单引号
        // 包裹并转义内嵌单引号，保证建议命令可粘贴进 shell。
        let safe = suggested_next_commands(&hit("aaaa", Some("bbbb")));
        assert_eq!(
            safe[0],
            "agent-session-grep get-message msg_v1_aaaa --session bbbb --around 2"
        );
        assert_eq!(safe[1], "agent-session-grep context bbbb");
        let spaced = suggested_next_commands(&hit("msg with space", Some("ses'quote")));
        assert_eq!(
            spaced[0],
            "agent-session-grep get-message 'msg_v1_msg with space' --session 'ses'\\''quote' --around 2"
        );
        assert_eq!(spaced[1], "agent-session-grep context 'ses'\\''quote'");
    }
}
