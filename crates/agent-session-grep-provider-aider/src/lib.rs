//! Aider provider adapter.
//!
//! Parses Aider's `.aider.chat.history.md` Markdown format. A single file
//! accumulates many runs (one per aider launch), each delimited by a
//! "# aider chat started at <ts>" header. Roles are reconstructed from
//! line prefixes:
//!   - "#### <text>" → user prompt (Markdown h4)
//!   - plain text after a turn → assistant response
//!   - "> <text>" → aider tool/edit output (blockquote)
//!
//! Format evidence: agentsview (MIT) `internal/parser/aider.go`.
//! The line-prefix role reconstruction is adapted from agentsview under MIT.

use agent_session_grep_ports::{
    AdapterManifest, CanonicalEventSink, Confidence, MessageEvent, ParseReport, ProbeResult,
    ProviderAdapter, ProviderError, manifest_for,
};

/// Variant id surfaced in probe results.
const VARIANT_ID: &str = "aider/chat-history-md-v1";

/// Number of non-blank lines to sample during probe (bounded, RFC-0002 §7).
const SAMPLE_LINE_LIMIT: usize = 20;

/// Aider adapter: parses `.aider.chat.history.md` Markdown format.
pub struct AiderAdapter;

impl AiderAdapter {
    pub fn new() -> Self {
        Self
    }
}

impl Default for AiderAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl ProviderAdapter for AiderAdapter {
    fn provider_id(&self) -> &str {
        "aider"
    }

    fn manifest(&self) -> AdapterManifest {
        manifest_for(
            self.provider_id(),
            Some(1),
            &[
                "spans are derived approximations (block start + text length), not byte-exact line slices",
                "tool/edit blockquote output is folded into assistant text",
                "session identity is the first `# aider chat started at` header timestamp",
            ],
        )
    }

    fn probe(&self, bytes: &[u8]) -> Result<ProbeResult, ProviderError> {
        let text = std::str::from_utf8(bytes)
            .map_err(|e| ProviderError::StructuralFatal(format!("not valid UTF-8: {e}")))?;
        let text = text.strip_prefix('\u{feff}').unwrap_or(text);

        let mut matched = Vec::new();
        let unmatched = Vec::new();

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

        let mut headers = 0usize;
        let mut user_prompts = 0usize;

        for &(line_no, line) in &sample {
            let trimmed = line.trim_start();
            if trimmed.starts_with("# aider chat started at ") {
                headers += 1;
            } else if trimmed.starts_with("#### ") {
                user_prompts += 1;
            }
            let _ = line_no;
        }

        // Aider is distinct: "# aider chat started at" header + "#### " prompts.
        // Refuse if no Aider-specific markers present.
        if headers == 0 && user_prompts == 0 {
            return Err(ProviderError::AmbiguousVariant(
                "no Aider header or user prompt markers found in sampled lines".into(),
            ));
        }

        let confidence = if headers > 0 && user_prompts > 0 {
            matched.push(format!(
                "{headers} chat headers, {user_prompts} user prompts"
            ));
            Confidence::Confirmed
        } else if headers > 0 {
            matched.push(format!("{headers} chat headers found"));
            Confidence::High
        } else {
            matched.push(format!("{user_prompts} user prompts found"));
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
        let text = std::str::from_utf8(bytes)
            .map_err(|e| ProviderError::StructuralFatal(format!("not valid UTF-8: {e}")))?;

        let mut report = ParseReport::default();
        let mut seq: u32 = 0;
        let mut offset: u64 = 0;

        // Track current role and accumulate text for assistant blocks.
        let mut current_role: Option<&str> = None;
        let mut current_text = String::new();
        let mut current_start: u64 = 0;

        let flush = |role: &str,
                     text: &mut String,
                     start: &mut u64,
                     seq: &mut u32,
                     report: &mut ParseReport,
                     sink: &mut dyn CanonicalEventSink|
         -> Result<(), ProviderError> {
            if text.trim().is_empty() {
                text.clear();
                return Ok(());
            }
            let end = *start + text.len() as u64;
            sink.emit_message(MessageEvent {
                seq: *seq,
                native_id: &format!("aider-msg-{seq}"),
                parent_native_id: None,
                role,
                text: text.trim(),
                timestamp: None,
                is_sidechain: false,
                span: Some((*start, end)),
            })
            .map_err(|e| ProviderError::StructuralFatal(e.to_string()))?;
            *seq += 1;
            report.committed += 1;
            text.clear();
            Ok(())
        };

        for (line_no, raw_line) in text.split_inclusive('\n').enumerate() {
            let start = offset;
            offset += raw_line.len() as u64;
            let line = raw_line.strip_suffix('\n').unwrap_or(raw_line);
            let line = line.strip_suffix('\r').unwrap_or(line);
            let parse_line = if line_no == 0 {
                line.strip_prefix('\u{feff}').unwrap_or(line)
            } else {
                line
            };
            let trimmed = parse_line.trim_start();

            if trimmed.starts_with("# aider chat started at ") {
                // Flush pending assistant text, then start a new run.
                if let Some(role) = current_role {
                    flush(
                        role,
                        &mut current_text,
                        &mut current_start,
                        &mut seq,
                        &mut report,
                        sink,
                    )?;
                }
                current_role = None;
                // Session header: extract timestamp as session identity hint.
                if report.session_native_id.is_none()
                    && let Some(ts) = trimmed.strip_prefix("# aider chat started at ")
                {
                    report.session_native_id = Some(ts.trim().to_string());
                }
                continue;
            }

            if let Some(rest) = trimmed.strip_prefix("#### ") {
                // User prompt: flush previous, emit new user message.
                if let Some(role) = current_role {
                    flush(
                        role,
                        &mut current_text,
                        &mut current_start,
                        &mut seq,
                        &mut report,
                        sink,
                    )?;
                }
                current_role = Some("user");
                current_text = rest.to_string();
                current_start = start;
            } else if trimmed.starts_with("> ") {
                // Tool/edit output (blockquote): treat as system/assistant context.
                // Append to current assistant block, or start one.
                if current_role.is_none() {
                    current_role = Some("assistant");
                    current_start = start;
                }
                if !current_text.is_empty() {
                    current_text.push('\n');
                }
                current_text.push_str(trimmed.strip_prefix("> ").unwrap_or(trimmed));
            } else if !parse_line.trim().is_empty() {
                // Plain text: assistant response.
                if current_role.is_none() || current_role == Some("user") {
                    if let Some(role) = current_role {
                        flush(
                            role,
                            &mut current_text,
                            &mut current_start,
                            &mut seq,
                            &mut report,
                            sink,
                        )?;
                    }
                    current_role = Some("assistant");
                    current_start = start;
                }
                if !current_text.is_empty() {
                    current_text.push('\n');
                }
                current_text.push_str(parse_line.trim());
            }
        }

        // Flush remaining.
        if let Some(role) = current_role {
            flush(
                role,
                &mut current_text,
                &mut current_start,
                &mut seq,
                &mut report,
                sink,
            )?;
        }

        Ok(report)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_matches_provider_matrix() {
        let adapter = AiderAdapter::new();
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
    }
    impl CanonicalEventSink for CountSink {
        fn emit_message(
            &mut self,
            _event: MessageEvent<'_>,
        ) -> agent_session_grep_ports::PortResult<()> {
            self.count += 1;
            Ok(())
        }
    }

    #[test]
    fn probe_rejects_empty_input() {
        let adapter = AiderAdapter::new();
        assert!(adapter.probe(b"").is_err());
    }

    #[test]
    fn probe_rejects_non_aider_markdown() {
        let adapter = AiderAdapter::new();
        let fixture = "# Some random markdown\n\nHello world\n";
        assert!(adapter.probe(fixture.as_bytes()).is_err());
    }

    #[test]
    fn probe_confirms_aider_header_and_prompts() {
        let adapter = AiderAdapter::new();
        let fixture =
            "# aider chat started at 2026-01-01 12:00:00\n\n#### Hello, can you help me?\n";
        let result = adapter.probe(fixture.as_bytes()).unwrap();
        assert_eq!(result.variant_id, VARIANT_ID);
        assert_eq!(result.confidence, Confidence::Confirmed);
    }

    #[test]
    fn probe_high_confidence_header_only() {
        let adapter = AiderAdapter::new();
        let fixture = "# aider chat started at 2026-01-01 12:00:00\n";
        let result = adapter.probe(fixture.as_bytes()).unwrap();
        assert_eq!(result.confidence, Confidence::High);
    }

    #[test]
    fn parse_extracts_user_and_assistant() {
        let adapter = AiderAdapter::new();
        let fixture = "# aider chat started at 2026-01-01 12:00:00\n\n#### What is Rust?\n\nRust is a systems programming language.\n";
        let mut sink = CountSink { count: 0 };
        let report = adapter.parse(fixture.as_bytes(), &mut sink).unwrap();
        assert_eq!(sink.count, 2);
        assert_eq!(report.committed, 2);
    }

    #[test]
    fn parse_extracts_session_id_from_header() {
        let adapter = AiderAdapter::new();
        let fixture = "# aider chat started at 2026-01-01 12:00:00\n\n#### Hello\n";
        let mut sink = CountSink { count: 0 };
        let report = adapter.parse(fixture.as_bytes(), &mut sink).unwrap();
        assert_eq!(
            report.session_native_id.as_deref(),
            Some("2026-01-01 12:00:00")
        );
    }

    #[test]
    fn parse_handles_blockquote_tool_output() {
        let adapter = AiderAdapter::new();
        let fixture = "# aider chat started at 2026-01-01 12:00:00\n\n#### Edit this file\n\n> Applied edit to src/main.rs\n\nDone editing.\n";
        let mut sink = CountSink { count: 0 };
        let report = adapter.parse(fixture.as_bytes(), &mut sink).unwrap();
        assert!(report.committed >= 2);
    }

    #[test]
    fn parse_handles_multiple_runs() {
        let adapter = AiderAdapter::new();
        let fixture = "# aider chat started at 2026-01-01 12:00:00\n\n#### First question\n\nFirst answer.\n\n# aider chat started at 2026-01-01 13:00:00\n\n#### Second question\n\nSecond answer.\n";
        let mut sink = CountSink { count: 0 };
        let report = adapter.parse(fixture.as_bytes(), &mut sink).unwrap();
        assert_eq!(report.committed, 4);
    }
}
