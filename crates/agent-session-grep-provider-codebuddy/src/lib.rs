//! Tencent CodeBuddy CLI provider adapter.
//!
//! Parses CodeBuddy's CLI session JSONL format. Each line is a
//! `CodeBuddyConversationLine`: a top-level JSON object with a `type`
//! discriminator. `type: "message"` records carry `role` (user/assistant/system)
//! and `content` at the top level (OpenAI-style), plus a `sessionId`.
//!
//! CodeBuddy records a startup keyword as a root user message whose content
//! is the literal `"code"`; per the upstream evidence (AgentRecall
//! `codebuddy-cli` source, MIT), that root message is filtered out — it is not
//! a real user turn, only a launcher token.
//!
//! Format evidence: AgentRecall (`codebuddy-cli` source, MIT). The
//! `type:"message"` dispatch, top-level `role`/`content`, `sessionId` identity,
//! and `"code"` root-message filter are adapted idea-level from AgentRecall
//! under its MIT license.
//!
//! Variant ID: `tencent-codebuddy/cli-jsonl-v1`.

use agent_session_grep_ports::MetadataResolution;
use agent_session_grep_ports::{
    AdapterManifest, CanonicalEventSink, Confidence, MessageEvent, ParseReport, ProbeResult,
    ProviderAdapter, ProviderError, manifest_for,
};

/// Variant id surfaced in probe results.
const VARIANT_ID: &str = "tencent-codebuddy/cli-jsonl-v1";

/// Number of non-blank lines to sample during probe (bounded, RFC-0002 §7).
const SAMPLE_LINE_LIMIT: usize = 8;

/// Root startup-keyword message filtered out (PRD: filter root user message
/// with content `"code"`). Kept as a named constant for clarity.
const ROOT_STARTUP_KEYWORD: &str = "code";

/// Tencent CodeBuddy CLI adapter: parses CLI session JSONL.
pub struct CodeBuddyAdapter;

impl CodeBuddyAdapter {
    pub fn new() -> Self {
        Self
    }
}

impl Default for CodeBuddyAdapter {
    fn default() -> Self {
        Self::new()
    }
}

/// Minimal deserialization target for a CodeBuddy conversation line.
///
/// Only fields needed for probe/parse are modeled; unknown fields are silently
/// ignored (forward-compatible).
#[derive(serde::Deserialize)]
struct CodeBuddyLine {
    #[serde(default)]
    r#type: String,
    #[serde(default)]
    role: String,
    #[serde(default)]
    content: Option<serde_json::Value>,
    #[serde(default, rename = "sessionId")]
    session_id: Option<String>,
    #[serde(default)]
    timestamp: Option<String>,
}

impl ProviderAdapter for CodeBuddyAdapter {
    fn provider_id(&self) -> &str {
        "tencent-codebuddy"
    }

    fn manifest(&self) -> AdapterManifest {
        manifest_for(
            self.provider_id(),
            Some(1),
            &[
                "the root startup-keyword user message (content: \"code\") is filtered out",
                "no working-directory pair observation (no separate cwd-bearing header record)",
                "native message ids are not preserved (synthetic codebuddy-msg-{seq})",
            ],
        )
    }

    fn probe(&self, bytes: &[u8]) -> Result<ProbeResult, ProviderError> {
        let text = std::str::from_utf8(bytes)
            .map_err(|e| ProviderError::StructuralFatal(format!("not valid UTF-8: {e}")))?;
        let text = text.strip_prefix('\u{feff}').unwrap_or(text);

        let mut matched = Vec::new();
        let mut unmatched = Vec::new();

        let mut sample: Vec<(usize, &str)> = Vec::new();
        for (idx, line) in text.lines().enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            if sample.len() == SAMPLE_LINE_LIMIT {
                break;
            }
            sample.push((idx + 1, line));
        }

        if sample.is_empty() {
            return Err(ProviderError::AmbiguousVariant(
                "empty input: no non-blank lines to probe".into(),
            ));
        }

        let mut json_lines = 0usize;
        let mut message_records = 0usize;
        let mut top_level_role = 0usize;
        let mut nested_message_role = 0usize;
        let mut conversational = 0usize;

        for &(line_no, line) in &sample {
            match serde_json::from_str::<serde_json::Value>(line) {
                Ok(v) => {
                    json_lines += 1;
                    let t = v
                        .get("type")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("");
                    if t == "message" {
                        message_records += 1;
                        // CodeBuddy carries role/content at the top level. A
                        // nested `message.role` would indicate a different
                        // OpenAI-style provider (e.g. a ChatGPT export) and is
                        // tracked separately to refuse ambiguous inputs.
                        let top_role = v
                            .get("role")
                            .and_then(serde_json::Value::as_str)
                            .unwrap_or("");
                        if !top_role.is_empty() {
                            top_level_role += 1;
                            if matches!(top_role, "user" | "assistant") {
                                conversational += 1;
                            }
                        }
                        if v.pointer("/message/role")
                            .and_then(serde_json::Value::as_str)
                            .is_some()
                        {
                            nested_message_role += 1;
                        }
                    }
                }
                Err(_) => {
                    unmatched.push(format!("line {line_no}: not valid JSON"));
                }
            }
        }

        if json_lines == 0 {
            return Err(ProviderError::AmbiguousVariant(format!(
                "no JSON lines parsed in {} sampled lines",
                sample.len()
            )));
        }

        matched.push(format!("{json_lines} sampled lines are valid JSON"));

        // CodeBuddy CLI is distinct: `type:"message"` with role/content at the
        // top level (not nested under `message`). Claude uses `type:"user"|"assistant"`
        // with nested `message`; Pi/Kimi use `type:"session"`/`type:"context.append_message"`
        // with nested `message`. Refuse if no CodeBuddy `type:"message"` markers are
        // present, or if a competing nested-message shape is detected (would
        // collide with other adapters and cause ambiguous selection).
        if message_records == 0 {
            return Err(ProviderError::AmbiguousVariant(
                "no CodeBuddy `type:\"message\"` records found in sampled lines".into(),
            ));
        }
        if nested_message_role > 0 && top_level_role == 0 {
            return Err(ProviderError::AmbiguousVariant(
                "records carry nested `message.role` without a top-level `role` — \
                 not CodeBuddy CLI shape"
                    .into(),
            ));
        }
        if top_level_role == 0 {
            return Err(ProviderError::AmbiguousVariant(
                "`type:\"message\"` records found but none carry a top-level `role`".into(),
            ));
        }

        let confidence = if conversational > 0 {
            matched.push(format!(
                "{message_records} message records, {conversational} conversational"
            ));
            Confidence::Confirmed
        } else {
            matched.push(format!("{message_records} message records found"));
            Confidence::High
        };

        Ok(ProbeResult {
            variant_id: VARIANT_ID.to_string(),
            confidence,
            matched_evidence: matched,
            unmatched_evidence: unmatched,
        })
    }

    fn parse(
        &self,
        bytes: &[u8],
        sink: &mut dyn CanonicalEventSink,
    ) -> Result<ParseReport, ProviderError> {
        // 字节兼容路径：把整段字节包成只读切片源，与生产流式路径共用同一实现。
        let source = agent_session_grep_ports::SliceSource::new(bytes);
        self.parse_source(&source, sink)
    }

    fn parse_source(
        &self,
        source: &dyn agent_session_grep_ports::ReadOnlySource,
        sink: &mut dyn CanonicalEventSink,
    ) -> Result<ParseReport, ProviderError> {
        // 流式逐行读取：内存上界是单条记录（manifest max_record_size），
        // 不是文件大小（RFC-0002 §7）。
        let mut lines = agent_session_grep_ports::BoundedLineReader::new(
            source,
            agent_session_grep_ports::STREAM_RECORD_MAX_BYTES,
        )
        .map_err(|e| ProviderError::Io(e.to_string()))?;

        let mut report = ParseReport::default();
        let mut seq: u32 = 0;
        let mut session_ids: Vec<String> = Vec::new();
        // The root user message is the first user turn in the file; the
        // startup keyword filter applies only to that single root turn.
        let mut root_user_seen = false;

        while let Some(line) = lines.next_record()? {
            // 行负载已由 BoundedLineReader 剥离 \n/\r 与首行 BOM，span 仍以
            // 快照字节为坐标系（start/end 与整段 parse 逐字节一致）。
            let parse_line = std::str::from_utf8(line.bytes)
                .map_err(|e| ProviderError::StructuralFatal(format!("not valid UTF-8: {e}")))?;
            let line_no = line.number - 1;
            let start = line.start;
            let end = line.end;
            if parse_line.trim().is_empty() {
                continue;
            }

            let rec: CodeBuddyLine = match serde_json::from_str(parse_line) {
                Ok(r) => r,
                Err(e) => {
                    report.skipped += 1;
                    report
                        .diagnostics
                        .push(format!("line {}: invalid JSON, skipped ({e})", line_no + 1));
                    continue;
                }
            };

            let span = Some((start, end));

            // Only `type:"message"` records are conversational; everything else
            // (metadata, tool, event records) is skipped for this slice.
            if rec.r#type != "message" {
                continue;
            }

            // Record session identity from any message line that carries a
            // sessionId (CodeBuddy repeats it per line). Pair-observation is
            // not meaningful here (no separate cwd-bearing header record).
            if let Some(id) = rec.session_id.as_deref()
                && !id.trim().is_empty()
            {
                let id = id.trim();
                if report.session_native_id.is_none() {
                    report.session_native_id = Some(id.to_string());
                    report.session_observation.provider_session_id =
                        MetadataResolution::Resolved(id.to_string());
                }
                if !session_ids.iter().any(|s| s == id) {
                    session_ids.push(id.to_string());
                }
            }

            let role = rec.role.as_str();
            // Skip non-conversational roles (system, tool, etc.).
            if !matches!(role, "user" | "assistant") {
                continue;
            }

            let content = rec.content.as_ref().unwrap_or(&serde_json::Value::Null);
            let text = codebuddy_content_text(content);
            if text.trim().is_empty() {
                continue;
            }

            // Filter the root startup-keyword user message: the FIRST user turn,
            // when its content is exactly the launcher token `"code"`. This is a
            // CodeBuddy startup artifact, not a real user request. Only the root
            // (first) user turn is eligible, so a later genuine "code" message
            // is preserved.
            if role == "user" && !root_user_seen {
                root_user_seen = true;
                if text.trim() == ROOT_STARTUP_KEYWORD {
                    continue;
                }
            }

            let timestamp = rec.timestamp.as_deref();
            sink.emit_message(MessageEvent {
                seq,
                native_id: &format!("codebuddy-msg-{seq}"),
                parent_native_id: None,
                role,
                text: &text,
                timestamp,
                is_sidechain: false,
                span,
            })
            .map_err(|e| ProviderError::StructuralFatal(e.to_string()))?;
            seq += 1;
            report.committed += 1;
        }

        // Multi-session diagnostic: a single source file should belong to one
        // session; multiple distinct sessionIds mean a merged/concatenated file.
        if session_ids.len() > 1 {
            report.session_observation.multi_session = true;
            report.session_observation.provider_session_id = MetadataResolution::Ambiguous;
            report.diagnostics.push(format!(
                "文件包含 {} 个不同 sessionId——单文件=单会话，全部消息归属首个会话 {}",
                session_ids.len(),
                session_ids[0]
            ));
        }

        Ok(report)
    }
}

/// Extract plain text from a CodeBuddy content value.
///
/// CodeBuddy content can be a string or an array of content parts (OpenAI
/// style: `{type:"text", text:"..."}`). Non-text parts (e.g. tool calls) are
/// skipped for this slice.
fn codebuddy_content_text(content: &serde_json::Value) -> String {
    match content {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Array(parts) => {
            let mut buf = String::new();
            for part in parts {
                if part.get("type").and_then(serde_json::Value::as_str) == Some("text")
                    && let Some(t) = part.get("text").and_then(serde_json::Value::as_str)
                {
                    if !buf.is_empty() {
                        buf.push('\n');
                    }
                    buf.push_str(t);
                }
            }
            buf
        }
        _ => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_matches_provider_matrix() {
        let adapter = CodeBuddyAdapter::new();
        let manifest = adapter.manifest();
        assert_eq!(manifest.provider_id, adapter.provider_id());
        assert_eq!(manifest.supported_variants, vec![VARIANT_ID.to_string()]);
        assert_eq!(manifest.capabilities.provider_id, adapter.provider_id());
        assert_eq!(manifest.capabilities.variant_id, VARIANT_ID);
        assert!(manifest.last_certified_targets.is_empty());
        assert_eq!(manifest.fixture_revision, Some(1));
    }

    struct CountSink {
        count: usize,
        texts: Vec<String>,
        roles: Vec<String>,
    }
    impl CanonicalEventSink for CountSink {
        fn emit_message(
            &mut self,
            event: MessageEvent<'_>,
        ) -> agent_session_grep_ports::PortResult<()> {
            self.count += 1;
            self.texts.push(event.text.to_string());
            self.roles.push(event.role.to_string());
            Ok(())
        }
    }

    #[test]
    fn probe_rejects_empty_input() {
        let adapter = CodeBuddyAdapter::new();
        assert!(adapter.probe(b"").is_err());
    }

    #[test]
    fn probe_confirms_codebuddy_cli_jsonl() {
        let adapter = CodeBuddyAdapter::new();
        let fixture = r#"{"type":"message","role":"user","content":"hello","sessionId":"s-1","timestamp":"2026-01-01T00:00:00Z"}
{"type":"message","role":"assistant","content":"hi there","sessionId":"s-1"}
"#;
        let result = adapter.probe(fixture.as_bytes()).unwrap();
        assert_eq!(result.variant_id, VARIANT_ID);
        assert_eq!(result.confidence, Confidence::Confirmed);
    }

    #[test]
    fn probe_rejects_plain_json_without_message_type() {
        let adapter = CodeBuddyAdapter::new();
        let fixture = "{\"foo\":1}\n{\"bar\":2}\n";
        assert!(adapter.probe(fixture.as_bytes()).is_err());
    }

    #[test]
    fn probe_rejects_claude_shape_with_nested_message_role() {
        // Claude Code shape: type is the role, message is nested. Must NOT
        // match CodeBuddy (which has type:"message" + top-level role).
        let adapter = CodeBuddyAdapter::new();
        let fixture = r#"{"type":"user","message":{"role":"user","content":"hi"}}
{"type":"assistant","message":{"role":"assistant","content":"hello"}}
"#;
        assert!(adapter.probe(fixture.as_bytes()).is_err());
    }

    #[test]
    fn probe_rejects_pi_session_shape() {
        let adapter = CodeBuddyAdapter::new();
        let fixture = r#"{"type":"session","id":"s1","cwd":"/p"}
{"type":"message","message":{"role":"user","content":"hi"}}
"#;
        assert!(adapter.probe(fixture.as_bytes()).is_err());
    }

    #[test]
    fn parse_extracts_messages_and_session_id() {
        let adapter = CodeBuddyAdapter::new();
        let fixture = r#"{"type":"message","role":"user","content":"hello world","sessionId":"sess-1","timestamp":"2026-01-01T00:00:00Z"}
{"type":"message","role":"assistant","content":"hi there","sessionId":"sess-1"}
"#;
        let mut sink = CountSink {
            count: 0,
            texts: vec![],
            roles: vec![],
        };
        let report = adapter.parse(fixture.as_bytes(), &mut sink).unwrap();
        assert_eq!(sink.count, 2);
        assert_eq!(report.committed, 2);
        assert_eq!(report.session_native_id.as_deref(), Some("sess-1"));
        assert_eq!(
            sink.roles,
            vec!["user".to_string(), "assistant".to_string()]
        );
    }

    #[test]
    fn parse_filters_root_code_startup_message() {
        let adapter = CodeBuddyAdapter::new();
        let fixture = r#"{"type":"message","role":"user","content":"code","sessionId":"s1"}
{"type":"message","role":"user","content":"real question","sessionId":"s1"}
{"type":"message","role":"assistant","content":"answer","sessionId":"s1"}
"#;
        let mut sink = CountSink {
            count: 0,
            texts: vec![],
            roles: vec![],
        };
        let report = adapter.parse(fixture.as_bytes(), &mut sink).unwrap();
        assert_eq!(sink.count, 2);
        assert_eq!(report.committed, 2);
        // The "code" root message must not appear in emitted texts.
        assert!(!sink.texts.iter().any(|t| t == "code"));
    }

    #[test]
    fn parse_preserves_non_root_code_message() {
        // A later user message that happens to be "code" is NOT filtered —
        // only the root (first) user turn is eligible for the startup filter.
        let adapter = CodeBuddyAdapter::new();
        let fixture = r#"{"type":"message","role":"user","content":"real question","sessionId":"s1"}
{"type":"message","role":"assistant","content":"answer","sessionId":"s1"}
{"type":"message","role":"user","content":"code","sessionId":"s1"}
"#;
        let mut sink = CountSink {
            count: 0,
            texts: vec![],
            roles: vec![],
        };
        let report = adapter.parse(fixture.as_bytes(), &mut sink).unwrap();
        assert_eq!(report.committed, 3);
        assert!(sink.texts.iter().any(|t| t == "code"));
    }

    #[test]
    fn parse_skips_non_message_types() {
        let adapter = CodeBuddyAdapter::new();
        let fixture = r#"{"type":"meta","sessionId":"s1","cwd":"/p"}
{"type":"event","event":"tool_call"}
{"type":"message","role":"user","content":"real msg","sessionId":"s1"}
"#;
        let mut sink = CountSink {
            count: 0,
            texts: vec![],
            roles: vec![],
        };
        let report = adapter.parse(fixture.as_bytes(), &mut sink).unwrap();
        assert_eq!(report.committed, 1);
        assert_eq!(sink.count, 1);
    }

    #[test]
    fn parse_skips_system_role() {
        let adapter = CodeBuddyAdapter::new();
        let fixture = r#"{"type":"message","role":"system","content":"system prompt","sessionId":"s1"}
{"type":"message","role":"user","content":"hi","sessionId":"s1"}
"#;
        let mut sink = CountSink {
            count: 0,
            texts: vec![],
            roles: vec![],
        };
        let report = adapter.parse(fixture.as_bytes(), &mut sink).unwrap();
        assert_eq!(report.committed, 1);
        assert_eq!(sink.roles, vec!["user".to_string()]);
    }

    #[test]
    fn parse_handles_array_content_parts() {
        let adapter = CodeBuddyAdapter::new();
        let fixture = r#"{"type":"message","role":"assistant","content":[{"type":"text","text":"part1"},{"type":"text","text":"part2"}],"sessionId":"s1"}
"#;
        let mut sink = CountSink {
            count: 0,
            texts: vec![],
            roles: vec![],
        };
        let report = adapter.parse(fixture.as_bytes(), &mut sink).unwrap();
        assert_eq!(report.committed, 1);
        assert_eq!(sink.texts[0], "part1\npart2");
    }

    #[test]
    fn parse_skips_invalid_json_lines() {
        let adapter = CodeBuddyAdapter::new();
        let fixture = "not json\n{\"type\":\"message\",\"role\":\"user\",\"content\":\"ok\",\"sessionId\":\"s1\"}\n";
        let mut sink = CountSink {
            count: 0,
            texts: vec![],
            roles: vec![],
        };
        let report = adapter.parse(fixture.as_bytes(), &mut sink).unwrap();
        assert_eq!(report.committed, 1);
        assert_eq!(report.skipped, 1);
    }

    #[test]
    fn parse_multi_session_emits_diagnostic() {
        let adapter = CodeBuddyAdapter::new();
        let fixture = r#"{"type":"message","role":"user","content":"msg1","sessionId":"s1"}
{"type":"message","role":"user","content":"msg2","sessionId":"s2"}
"#;
        let mut sink = CountSink {
            count: 0,
            texts: vec![],
            roles: vec![],
        };
        let report = adapter.parse(fixture.as_bytes(), &mut sink).unwrap();
        assert_eq!(report.committed, 2);
        assert!(!report.diagnostics.is_empty());
        assert!(report.session_observation.multi_session);
    }

    #[test]
    fn provider_id_is_stable() {
        let adapter = CodeBuddyAdapter::new();
        assert_eq!(adapter.provider_id(), "tencent-codebuddy");
    }
}
