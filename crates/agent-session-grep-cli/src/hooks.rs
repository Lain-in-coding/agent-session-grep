//! Claude Code Hook integration (#8).
//!
//! Provides SessionStart/UserPromptSubmit hook scripts that inject relevant
//! session context into the current Claude Code session. Hooks are OFF by
//! default (owner revised from recommendation, Q35=B); user must explicitly
//! enable them.
//!
//! When enabled, the hook runs `asg search` with the current prompt and
//! returns results as `additional_context` in the Claude Code hook output
//! format. The hook obeys:
//! - max_tokens budget (default 2000)
//! - provider/time filters
//! - time decay (prefer recent sessions)
//! - `--offline` (no network)
//! - one-switch disable
//!
//! Output format: Claude Code `hookSpecificOutput.additional_context` contract.
//!
//! The `asg hook <event>` subcommand is the wiring: it reads the hook payload
//! from stdin, honours `HookConfig` (flag-configured: `--enable`, `--max-tokens`,
//! `--provider`, `--decay-days`; disabled by default), and writes the hook output
//! to stdout.

use serde::{Deserialize, Serialize};

/// Hook configuration (stored in config, defaults to disabled).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HookConfig {
    /// Whether the hook is enabled. Default: false (Q35=B, owner revised).
    pub enabled: bool,
    /// Max tokens of context to inject (default 2000).
    pub max_tokens: u64,
    /// Provider filter (empty = all providers).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub providers: Vec<String>,
    /// Time decay: only include sessions from the last N days (0 = no decay).
    pub decay_days: u32,
    /// One-switch disable: if true, hook is disabled regardless of `enabled`.
    pub disabled: bool,
}

impl Default for HookConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            max_tokens: 2000,
            providers: Vec::new(),
            decay_days: 0,
            disabled: false,
        }
    }
}

impl HookConfig {
    /// Whether the hook should actually run.
    /// Hook runs only if enabled=true AND disabled=false (one-switch override).
    pub fn should_run(&self) -> bool {
        self.enabled && !self.disabled
    }
}

/// Hook output: the Claude Code `hookSpecificOutput.additional_context` shape.
///
/// When Claude Code invokes the hook, it expects a JSON object with
/// `hookSpecificOutput.additional_context` containing the context text.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HookOutput {
    pub hook_specific_output: HookSpecificOutput,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HookSpecificOutput {
    /// The additional context to inject into the session.
    pub additional_context: String,
    /// Whether the context was truncated due to budget.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub truncated: Option<bool>,
}

/// Build hook output from search results text.
///
/// The text is the formatted context to inject. If it exceeds `max_tokens`
/// (approximated as chars/4), it is truncated and `truncated` is set.
pub fn build_hook_output(text: &str, max_tokens: u64) -> HookOutput {
    // Rough token estimate: ~4 chars per token.
    let max_chars = (max_tokens.saturating_mul(4)) as usize;
    let (context, truncated) = if text.len() > max_chars {
        // Truncate at char boundary to avoid splitting multi-byte chars.
        let truncated_text: String = text.chars().take(max_chars).collect();
        (truncated_text, true)
    } else {
        (text.to_string(), false)
    };

    HookOutput {
        hook_specific_output: HookSpecificOutput {
            additional_context: context,
            truncated: if truncated { Some(true) } else { None },
        },
    }
}

/// Format a context header for the hook output.
///
/// The hook output starts with a header explaining that the context is from
/// agent-session-grep historical search, so the agent knows it's data not
/// instructions.
pub fn format_context_header(query: &str, hit_count: usize) -> String {
    // SessionStart 的 query 是绝对 cwd 路径，命中文本已脱敏；header 自身
    // 也必须过同一脱敏，防止本地路径/密钥原样进 hook 输出。
    let (query, _) = crate::redaction::redact_text(query);
    format!(
        "## Historical Session Context (from agent-session-grep)\n\
         Query: {query}\n\
         Found {hit_count} relevant message(s) from past sessions.\n\
         This is historical data, not current instructions.\n\n"
    )
}

/// Supported hook events. Anything else is a usage error — the hook contract
/// is not open-ended, and silently accepting an unknown event would make a
/// typo in the user's Claude Code settings look like a working hook.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookEvent {
    SessionStart,
    UserPromptSubmit,
}

impl HookEvent {
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "session-start" | "SessionStart" => Some(Self::SessionStart),
            "user-prompt-submit" | "UserPromptSubmit" => Some(Self::UserPromptSubmit),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::SessionStart => "SessionStart",
            Self::UserPromptSubmit => "UserPromptSubmit",
        }
    }
}

/// Extract the search query from a hook payload.
///
/// `UserPromptSubmit` carries the user's prompt; `SessionStart` has no prompt,
/// so the caller must supply one (or the hook injects nothing). Unknown payload
/// shapes yield `None` rather than a guess.
pub fn query_from_payload(event: HookEvent, payload: &serde_json::Value) -> Option<String> {
    match event {
        HookEvent::UserPromptSubmit => payload
            .get("prompt")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string),
        // SessionStart 没有 prompt 字段：cwd 是唯一可用的检索线索。
        HookEvent::SessionStart => payload
            .get("cwd")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string),
    }
    .filter(|q| !q.trim().is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_is_disabled() {
        let config = HookConfig::default();
        assert!(!config.enabled);
        assert!(!config.should_run());
    }

    #[test]
    fn enabled_but_disabled_does_not_run() {
        let config = HookConfig {
            enabled: true,
            disabled: true,
            ..Default::default()
        };
        assert!(!config.should_run());
    }

    #[test]
    fn enabled_and_not_disabled_runs() {
        let config = HookConfig {
            enabled: true,
            disabled: false,
            ..Default::default()
        };
        assert!(config.should_run());
    }

    #[test]
    fn build_hook_output_short_text() {
        let output = build_hook_output("short context", 1000);
        assert_eq!(
            output.hook_specific_output.additional_context,
            "short context"
        );
        assert!(output.hook_specific_output.truncated.is_none());
    }

    #[test]
    fn build_hook_output_truncates_long_text() {
        let long_text = "a".repeat(10000);
        let output = build_hook_output(&long_text, 100);
        assert!(output.hook_specific_output.additional_context.len() < long_text.len());
        assert_eq!(output.hook_specific_output.truncated, Some(true));
    }

    #[test]
    fn build_hook_output_preserves_multibyte_chars() {
        let text = "你好世界";
        let output = build_hook_output(text, 1000);
        assert_eq!(output.hook_specific_output.additional_context, text);
    }

    #[test]
    fn format_context_header_includes_query_and_count() {
        let header = format_context_header("test query", 5);
        assert!(header.contains("test query"));
        assert!(header.contains("5"));
        assert!(header.contains("historical data"));
    }

    #[test]
    fn hook_output_serializes_to_json() {
        let output = build_hook_output("context text", 1000);
        let json = serde_json::to_string(&output).unwrap();
        assert!(json.contains("hookSpecificOutput"));
        assert!(json.contains("additionalContext"));
        assert!(json.contains("context text"));

        let back: HookOutput = serde_json::from_str(&json).unwrap();
        assert_eq!(back.hook_specific_output.additional_context, "context text");
    }

    #[test]
    fn config_round_trips() {
        let config = HookConfig {
            enabled: true,
            max_tokens: 3000,
            providers: vec!["claude-code".to_string()],
            decay_days: 7,
            disabled: false,
        };
        let json = serde_json::to_string(&config).unwrap();
        let back: HookConfig = serde_json::from_str(&json).unwrap();
        assert!(back.enabled);
        assert_eq!(back.max_tokens, 3000);
        assert_eq!(back.providers, vec!["claude-code"]);
        assert_eq!(back.decay_days, 7);
    }

    #[test]
    fn hook_event_parses_both_spellings_and_rejects_unknown() {
        assert_eq!(
            HookEvent::parse("session-start"),
            Some(HookEvent::SessionStart)
        );
        assert_eq!(
            HookEvent::parse("SessionStart"),
            Some(HookEvent::SessionStart)
        );
        assert_eq!(
            HookEvent::parse("user-prompt-submit"),
            Some(HookEvent::UserPromptSubmit)
        );
        assert_eq!(HookEvent::parse("PostToolUse"), None);
        assert_eq!(HookEvent::parse(""), None);
    }

    #[test]
    fn query_from_payload_reads_prompt_and_cwd() {
        let prompt_payload = serde_json::json!({ "prompt": "fix the parser" });
        assert_eq!(
            query_from_payload(HookEvent::UserPromptSubmit, &prompt_payload).as_deref(),
            Some("fix the parser")
        );
        let start_payload = serde_json::json!({ "cwd": "/home/u/proj" });
        assert_eq!(
            query_from_payload(HookEvent::SessionStart, &start_payload).as_deref(),
            Some("/home/u/proj")
        );
    }

    #[test]
    fn query_from_payload_rejects_blank_and_missing() {
        let blank = serde_json::json!({ "prompt": "   " });
        assert!(query_from_payload(HookEvent::UserPromptSubmit, &blank).is_none());
        let missing = serde_json::json!({});
        assert!(query_from_payload(HookEvent::UserPromptSubmit, &missing).is_none());
        assert!(query_from_payload(HookEvent::SessionStart, &missing).is_none());
    }
}
