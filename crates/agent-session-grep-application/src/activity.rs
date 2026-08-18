//! Structured tool activity extraction (#6).
//!
//! Extracts tool call/result abstractions from message payloads, enabling
//! search by "files read, commands run, failed tool calls". The extraction is
//! provider-agnostic: it works on the canonical message text/payload, not
//! provider-native fields.
//!
//! Reference: ctx (Apache-2.0) `provider_policy_event_text` grading (idea-only),
//! Recall (MIT) `events.rs` target priority chain (adapted).

use serde::{Deserialize, Serialize};

/// One structured tool activity event extracted from a message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolActivity {
    /// Kind of activity: tool call, tool result, file read, command run, etc.
    pub kind: ActivityKind,
    /// Who initiated the activity: user, assistant, or system.
    pub actor: ActivityActor,
    /// Tool or command name (e.g. "Read", "Bash", "Edit", "grep").
    pub name: String,
    /// Target of the activity: file path, command, query, etc.
    /// Extracted from the tool input or result via a priority chain.
    pub target: Option<String>,
    /// Outcome status: success, failure, or unknown.
    pub status: ActivityStatus,
    /// Short message or error text (bounded).
    pub message: Option<String>,
}

/// What kind of tool activity this is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActivityKind {
    /// A tool was invoked (e.g. Read, Bash, Edit, Write).
    ToolCall,
    /// A tool returned a result.
    ToolResult,
    /// A file was read or written.
    FileOperation,
    /// A shell command was executed.
    Command,
    /// A search or query was executed.
    Search,
}

impl ActivityKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ToolCall => "tool_call",
            Self::ToolResult => "tool_result",
            Self::FileOperation => "file_operation",
            Self::Command => "command",
            Self::Search => "search",
        }
    }
}

/// Who performed the activity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActivityActor {
    User,
    Assistant,
    System,
}

impl ActivityActor {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Assistant => "assistant",
            Self::System => "system",
        }
    }
}

/// Outcome of a tool activity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActivityStatus {
    Success,
    Failure,
    #[default]
    Unknown,
}

/// Extract structured tool activities from a canonical message payload.
///
/// The payload is a JSON value (the message's catalog payload). This function
/// looks for common tool-call patterns in the payload structure:
/// - Claude Code: `tool_use` / `tool_result` content blocks
/// - Codex: tool call/response in payload
/// - Generic: text patterns like "Running: <cmd>" or "Error: <msg>"
///
/// Returns a list of extracted activities (may be empty).
pub fn extract_activities(payload: &serde_json::Value) -> Vec<ToolActivity> {
    let mut activities = Vec::new();
    extract_from_content(payload, &mut activities);
    activities
}

/// Recursively extract from JSON content, looking for tool-call patterns.
fn extract_from_content(value: &serde_json::Value, activities: &mut Vec<ToolActivity>) {
    match value {
        serde_json::Value::Array(arr) => {
            for item in arr {
                extract_from_content_item(item, activities);
            }
        }
        serde_json::Value::Object(map) => {
            // Check for Claude-style tool_use block.
            if let Some(tool_name) = map.get("type").and_then(|v| v.as_str())
                && tool_name == "tool_use"
            {
                let name = map
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown")
                    .to_string();
                let input = map.get("input");
                let target = extract_target_from_input(input, &name);
                activities.push(ToolActivity {
                    kind: classify_tool(&name),
                    actor: ActivityActor::Assistant,
                    name,
                    target,
                    status: ActivityStatus::Unknown,
                    message: None,
                });
                return;
            }
            if let Some(tool_name) = map.get("type").and_then(|v| v.as_str())
                && tool_name == "tool_result"
            {
                let content = map.get("content");
                let (status, message) = classify_tool_result(content);
                activities.push(ToolActivity {
                    kind: ActivityKind::ToolResult,
                    actor: ActivityActor::Assistant,
                    name: "tool_result".to_string(),
                    target: None,
                    status,
                    message,
                });
                return;
            }
            // Recurse into nested objects.
            for (_, v) in map {
                extract_from_content(v, activities);
            }
        }
        _ => {}
    }
}

/// Extract a single content item (which may be an object with tool patterns).
fn extract_from_content_item(item: &serde_json::Value, activities: &mut Vec<ToolActivity>) {
    if let serde_json::Value::Object(_) = item {
        extract_from_content(item, activities);
    }
}

/// Extract the target (file path, command, etc.) from a tool input.
///
/// Priority chain (adapted from Recall's target extraction):
/// file_path > command > query > pattern > path > other string fields.
fn extract_target_from_input(input: Option<&serde_json::Value>, tool_name: &str) -> Option<String> {
    let input = input?;
    let obj = input.as_object()?;
    // Priority: file_path > command > query > pattern > path
    for key in &[
        "file_path",
        "command",
        "query",
        "pattern",
        "path",
        "filename",
    ] {
        if let Some(val) = obj.get(*key).and_then(|v| v.as_str())
            && !val.is_empty()
        {
            return Some(val.to_string());
        }
    }
    // Tool-specific: Bash commands may have "command" under different keys.
    if (tool_name == "Bash" || tool_name == "bash")
        && let Some(cmd) = obj.get("command").and_then(|v| v.as_str())
    {
        return Some(cmd.to_string());
    }
    None
}

/// Classify a tool name into an activity kind.
fn classify_tool(name: &str) -> ActivityKind {
    match name {
        "Read" | "read" | "Write" | "write" | "Edit" | "edit" | "MultiEdit" => {
            ActivityKind::FileOperation
        }
        "Bash" | "bash" | "Execute" | "execute" | "Shell" => ActivityKind::Command,
        "Grep" | "grep" | "Glob" | "glob" | "Search" | "search" => ActivityKind::Search,
        _ => ActivityKind::ToolCall,
    }
}

/// Classify a tool result content as success or failure.
fn classify_tool_result(content: Option<&serde_json::Value>) -> (ActivityStatus, Option<String>) {
    let content = match content {
        Some(c) => c,
        None => return (ActivityStatus::Unknown, None),
    };
    let text = match content {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Array(arr) => arr
            .iter()
            .filter_map(|v| v.get("text").and_then(|t| t.as_str()))
            .collect::<Vec<_>>()
            .join("\n"),
        _ => return (ActivityStatus::Unknown, None),
    };
    // Heuristic: "error" or "Error" in the first 200 chars → failure.
    let prefix = text.chars().take(200).collect::<String>();
    let lower = prefix.to_lowercase();
    if lower.contains("error") || lower.contains("failed") || lower.contains("exception") {
        let msg = prefix.chars().take(256).collect();
        (ActivityStatus::Failure, Some(msg))
    } else if !text.is_empty() {
        (ActivityStatus::Success, None)
    } else {
        (ActivityStatus::Unknown, None)
    }
}

/// Filter activities by kind. Returns only those matching the given kinds.
#[allow(clippy::needless_lifetimes)]
pub fn filter_by_kind<'a>(
    activities: &'a [ToolActivity],
    kinds: &[ActivityKind],
) -> Vec<&'a ToolActivity> {
    activities
        .iter()
        .filter(|a| kinds.contains(&a.kind))
        .collect()
}

/// Filter activities by status. Returns only those matching the given status.
#[allow(clippy::needless_lifetimes)]
pub fn filter_by_status<'a>(
    activities: &'a [ToolActivity],
    status: ActivityStatus,
) -> Vec<&'a ToolActivity> {
    activities.iter().filter(|a| a.status == status).collect()
}

/// Extract all target file paths from activities (for "files read" queries).
pub fn file_targets(activities: &[ToolActivity]) -> Vec<String> {
    activities
        .iter()
        .filter(|a| a.kind == ActivityKind::FileOperation)
        .filter_map(|a| a.target.clone())
        .collect()
}

/// Extract all command targets from activities (for "commands run" queries).
pub fn command_targets(activities: &[ToolActivity]) -> Vec<String> {
    activities
        .iter()
        .filter(|a| a.kind == ActivityKind::Command)
        .filter_map(|a| a.target.clone())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn extracts_tool_use_block() {
        let payload = json!({
            "content": [
                {"type": "tool_use", "name": "Read", "input": {"file_path": "/src/main.rs"}}
            ]
        });
        let activities = extract_activities(&payload);
        assert_eq!(activities.len(), 1);
        assert_eq!(activities[0].kind, ActivityKind::FileOperation);
        assert_eq!(activities[0].name, "Read");
        assert_eq!(activities[0].target.as_deref(), Some("/src/main.rs"));
    }

    #[test]
    fn extracts_bash_command() {
        let payload = json!({
            "content": [
                {"type": "tool_use", "name": "Bash", "input": {"command": "cargo test"}}
            ]
        });
        let activities = extract_activities(&payload);
        assert_eq!(activities.len(), 1);
        assert_eq!(activities[0].kind, ActivityKind::Command);
        assert_eq!(activities[0].target.as_deref(), Some("cargo test"));
    }

    #[test]
    fn extracts_tool_result_success() {
        let payload = json!({
            "content": [
                {"type": "tool_result", "content": "File contents here\nline 2"}
            ]
        });
        let activities = extract_activities(&payload);
        assert_eq!(activities.len(), 1);
        assert_eq!(activities[0].kind, ActivityKind::ToolResult);
        assert_eq!(activities[0].status, ActivityStatus::Success);
    }

    #[test]
    fn extracts_tool_result_failure() {
        let payload = json!({
            "content": [
                {"type": "tool_result", "content": "Error: file not found"}
            ]
        });
        let activities = extract_activities(&payload);
        assert_eq!(activities.len(), 1);
        assert_eq!(activities[0].status, ActivityStatus::Failure);
        assert!(activities[0].message.as_deref().unwrap().contains("Error"));
    }

    #[test]
    fn extracts_multiple_tools_from_array() {
        let payload = json!({
            "content": [
                {"type": "tool_use", "name": "Read", "input": {"file_path": "/a.rs"}},
                {"type": "tool_use", "name": "Bash", "input": {"command": "ls"}},
                {"type": "tool_use", "name": "Grep", "input": {"pattern": "fn main"}}
            ]
        });
        let activities = extract_activities(&payload);
        assert_eq!(activities.len(), 3);
    }

    #[test]
    fn no_activities_from_plain_text() {
        let payload = json!({"text": "hello world"});
        let activities = extract_activities(&payload);
        assert!(activities.is_empty());
    }

    #[test]
    fn filter_by_kind_returns_matching() {
        let payload = json!({
            "content": [
                {"type": "tool_use", "name": "Read", "input": {"file_path": "/a.rs"}},
                {"type": "tool_use", "name": "Bash", "input": {"command": "ls"}}
            ]
        });
        let activities = extract_activities(&payload);
        let commands = filter_by_kind(&activities, &[ActivityKind::Command]);
        assert_eq!(commands.len(), 1);
        assert_eq!(commands[0].name, "Bash");
    }

    #[test]
    fn filter_by_status_returns_failures() {
        let payload = json!({
            "content": [
                {"type": "tool_result", "content": "Error: bad"},
                {"type": "tool_result", "content": "ok"}
            ]
        });
        let activities = extract_activities(&payload);
        let failures = filter_by_status(&activities, ActivityStatus::Failure);
        assert_eq!(failures.len(), 1);
    }

    #[test]
    fn file_targets_extracts_file_paths() {
        let payload = json!({
            "content": [
                {"type": "tool_use", "name": "Read", "input": {"file_path": "/a.rs"}},
                {"type": "tool_use", "name": "Read", "input": {"file_path": "/b.rs"}},
                {"type": "tool_use", "name": "Bash", "input": {"command": "ls"}}
            ]
        });
        let activities = extract_activities(&payload);
        let files = file_targets(&activities);
        assert_eq!(files, vec!["/a.rs", "/b.rs"]);
    }

    #[test]
    fn command_targets_extracts_commands() {
        let payload = json!({
            "content": [
                {"type": "tool_use", "name": "Bash", "input": {"command": "cargo build"}},
                {"type": "tool_use", "name": "Read", "input": {"file_path": "/a.rs"}}
            ]
        });
        let activities = extract_activities(&payload);
        let cmds = command_targets(&activities);
        assert_eq!(cmds, vec!["cargo build"]);
    }

    #[test]
    fn activity_kind_as_str_round_trips() {
        for &k in &[
            ActivityKind::ToolCall,
            ActivityKind::ToolResult,
            ActivityKind::FileOperation,
            ActivityKind::Command,
            ActivityKind::Search,
        ] {
            let json = serde_json::to_string(&k).unwrap();
            assert!(json.contains(k.as_str()));
        }
    }
}
