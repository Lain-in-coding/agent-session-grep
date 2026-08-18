//! Antigravity CLI provider adapter.
//!
//! Parses Antigravity's transcript JSONL: per session, the CLI writes
//! `~/.gemini/antigravity-cli/brain/<session-uuid>/.system_generated/logs/
//! transcript.jsonl`. Each line is a step record carrying `step_index`
//! (monotonic sequence), `source` (USER_EXPLICIT / SYSTEM / MODEL / ...),
//! `type` (USER_INPUT / CONVERSATION_HISTORY / PLANNER_RESPONSE / ...),
//! `status`, `created_at` (ISO-8601), plus optional `content`, `thinking`,
//! and `tool_calls`.
//!
//! Only explicit user/model steps are conversational: `USER_EXPLICIT` maps
//! to `user`, `MODEL` to `assistant`; SYSTEM steps (including
//! CONVERSATION_HISTORY dumps) are never emitted as messages.
//!
//! Format evidence: local sample verification of
//! `~/.gemini/antigravity-cli/brain/` (structural shapes only).

use agent_session_grep_ports::{
    AdapterManifest, CanonicalEventSink, Confidence, MessageEvent, ParseReport, ProbeResult,
    ProviderAdapter, ProviderError, manifest_for,
};

/// Variant id surfaced in probe results.
const VARIANT_ID: &str = "antigravity/transcript-jsonl-v1";

/// Number of non-blank lines to sample during probe (bounded, RFC-0002 §7).
const SAMPLE_LINE_LIMIT: usize = 50;

/// Antigravity CLI adapter: parses `transcript.jsonl` step records.
///
/// The transcript itself carries no session id — identity lives in the
/// `brain/<uuid>` directory name, which the byte-stream contract cannot see.
/// The report therefore leaves identity unset and records the limitation in
/// diagnostics instead of fabricating an id.
pub struct AntigravityAdapter;

impl AntigravityAdapter {
    pub fn new() -> Self {
        Self
    }
}

impl Default for AntigravityAdapter {
    fn default() -> Self {
        Self::new()
    }
}

/// Minimal deserialization target for one Antigravity step record.
///
/// Only fields needed for probe/parse are modeled; unknown fields (status,
/// tool_calls, ...) are silently ignored (forward-compatible).
#[derive(serde::Deserialize)]
struct StepRecord {
    #[serde(default)]
    step_index: Option<u64>,
    #[serde(default)]
    source: Option<String>,
    #[serde(default)]
    r#type: Option<String>,
    #[serde(default)]
    created_at: Option<String>,
    #[serde(default)]
    content: Option<serde_json::Value>,
    #[serde(default)]
    thinking: Option<String>,
}

impl ProviderAdapter for AntigravityAdapter {
    fn provider_id(&self) -> &str {
        "antigravity"
    }

    fn manifest(&self) -> AdapterManifest {
        manifest_for(
            self.provider_id(),
            Some(1),
            &[
                "session identity lives in the brain/<uuid> directory name, not in the transcript file; session_native_id is left unset",
                "SYSTEM/CONVERSATION_HISTORY steps and tool activity are never emitted as messages",
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
        let mut step_records = 0usize;
        let mut source_records = 0usize;

        for &(line_no, line) in &sample {
            match serde_json::from_str::<serde_json::Value>(line) {
                Ok(v) => {
                    json_lines += 1;
                    if v.get("step_index").is_some() {
                        step_records += 1;
                        if v.get("source").is_some() {
                            source_records += 1;
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
                "no JSON lines parsed in {0} sampled lines",
                sample.len()
            )));
        }

        matched.push(format!("{json_lines} sampled lines are valid JSON"));

        // `step_index` is the Antigravity discriminator: refuse without it so
        // plain JSONL never competes with other adapters (RFC-0002 §3).
        if step_records == 0 {
            return Err(ProviderError::AmbiguousVariant(
                "no antigravity step_index records found in sampled lines".into(),
            ));
        }

        let confidence = if source_records > 0 {
            matched.push(format!(
                "{source_records} step records carry step_index + source"
            ));
            Confidence::Confirmed
        } else {
            matched.push(format!("{step_records} step records carry step_index"));
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

            let rec: StepRecord = match serde_json::from_str(parse_line) {
                Ok(r) => r,
                Err(e) => {
                    report.skipped += 1;
                    report
                        .diagnostics
                        .push(format!("line {}: invalid JSON, skipped ({e})", line_no + 1));
                    continue;
                }
            };

            // Only explicit user/model steps are conversational; SYSTEM steps
            // (context dumps, tool activity) are never user/assistant.
            let role = match rec.source.as_deref() {
                Some("USER_EXPLICIT") => "user",
                Some("MODEL") => "assistant",
                _ => continue,
            };
            // Conversation-history steps are context, not messages.
            if rec.r#type.as_deref() == Some("CONVERSATION_HISTORY") {
                continue;
            }

            let content = rec
                .content
                .as_ref()
                .and_then(serde_json::Value::as_str)
                .unwrap_or("");
            let thinking = rec.thinking.as_deref().unwrap_or("");
            let text = if !content.trim().is_empty() {
                content
            } else if !thinking.trim().is_empty() {
                // Thinking-only MODEL steps still carry searchable reasoning.
                thinking
            } else {
                continue;
            };

            let timestamp = rec.created_at.as_deref().filter(|t| is_rfc3339(t));
            let native_id = match rec.step_index {
                Some(i) => i.to_string(),
                None => format!("antigravity-msg-{seq}"),
            };

            sink.emit_message(MessageEvent {
                seq,
                native_id: &native_id,
                parent_native_id: None,
                role,
                text,
                timestamp,
                is_sidechain: false,
                span: Some((start, end)),
            })
            .map_err(|e| ProviderError::StructuralFatal(e.to_string()))?;
            seq += 1;
            report.committed += 1;
        }

        // The transcript has no session id field; identity lives in the
        // `brain/<uuid>` directory name, invisible to the byte-stream
        // contract. Left unset rather than fabricated.
        report
            .diagnostics
            .push("antigravity session identity lives in the brain/<uuid> directory name, not in the transcript file".into());

        Ok(report)
    }
}

/// Minimal RFC-3339 shape check for `created_at`:
/// `YYYY-MM-DDTHH:MM:SS` plus `Z`/`z`, an optional fractional part, or a
/// numeric `±HH:MM` offset. The provider's original string is passed through
/// unchanged; only clearly non-timestamp values yield `None`.
fn is_rfc3339(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() < 20
        || b[4] != b'-'
        || b[7] != b'-'
        || b[10] != b'T'
        || b[13] != b':'
        || b[16] != b':'
    {
        return false;
    }
    const DIGIT_POS: [usize; 14] = [0, 1, 2, 3, 5, 6, 8, 9, 11, 12, 14, 15, 17, 18];
    if !DIGIT_POS.iter().all(|&i| b[i].is_ascii_digit()) {
        return false;
    }

    let suffix = &s[19..];
    // Optional fractional seconds: `.digits` (followed by the zone).
    let suffix = match suffix.strip_prefix('.') {
        Some(fraction) => {
            let digits_end = fraction
                .as_bytes()
                .iter()
                .position(|c| !c.is_ascii_digit())
                .unwrap_or(fraction.len());
            if digits_end == 0 {
                return false;
            }
            &fraction[digits_end..]
        }
        None => suffix,
    };
    match suffix {
        "Z" | "z" => true,
        _ => {
            let ob = suffix.as_bytes();
            ob.len() == 6
                && (ob[0] == b'+' || ob[0] == b'-')
                && ob[1..3].iter().all(u8::is_ascii_digit)
                && ob[3] == b':'
                && ob[4..].iter().all(u8::is_ascii_digit)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_matches_provider_matrix() {
        let adapter = AntigravityAdapter::new();
        let manifest = adapter.manifest();
        assert_eq!(manifest.provider_id, adapter.provider_id());
        assert_eq!(manifest.supported_variants, vec![VARIANT_ID.to_string()]);
        assert_eq!(manifest.capabilities.provider_id, adapter.provider_id());
        assert_eq!(manifest.capabilities.variant_id, VARIANT_ID);
        assert!(manifest.last_certified_targets.is_empty());
        assert_eq!(manifest.fixture_revision, Some(1));
    }

    /// Synthetic Antigravity transcript (never real user data).
    fn transcript_fixture() -> String {
        r#"{"step_index":0,"source":"USER_EXPLICIT","type":"USER_INPUT","status":"DONE","created_at":"2026-07-03T13:22:14Z","content":"build the project"}
{"step_index":1,"source":"SYSTEM","type":"CONVERSATION_HISTORY","status":"DONE","created_at":"2026-07-03T13:22:15Z","content":"context dump"}
{"step_index":2,"source":"MODEL","type":"PLANNER_RESPONSE","status":"DONE","created_at":"2026-07-03T13:22:16Z","content":"plan accepted","thinking":"draft plan","tool_calls":[{"name":"view_file","args":{}}]}
"#
        .to_string()
    }

    struct RecordingSink {
        events: Vec<(u32, String, String, String, Option<String>)>,
    }
    impl CanonicalEventSink for RecordingSink {
        fn emit_message(
            &mut self,
            e: MessageEvent<'_>,
        ) -> agent_session_grep_ports::PortResult<()> {
            self.events.push((
                e.seq,
                e.native_id.to_string(),
                e.role.to_string(),
                e.text.to_string(),
                e.timestamp.map(str::to_string),
            ));
            Ok(())
        }
    }

    #[test]
    fn probe_rejects_empty_input() {
        let adapter = AntigravityAdapter::new();
        assert!(adapter.probe(b"").is_err());
    }

    #[test]
    fn probe_rejects_non_json_text() {
        let adapter = AntigravityAdapter::new();
        assert!(
            adapter
                .probe(b"this is not json\nneither is this\n")
                .is_err()
        );
    }

    #[test]
    fn probe_rejects_plain_jsonl() {
        let adapter = AntigravityAdapter::new();
        let fixture = "{\"foo\":1}\n{\"bar\":2}\n";
        assert!(adapter.probe(fixture.as_bytes()).is_err());
    }

    #[test]
    fn probe_confirms_antigravity_transcript() {
        let adapter = AntigravityAdapter::new();
        let result = adapter.probe(transcript_fixture().as_bytes()).unwrap();
        assert_eq!(result.variant_id, VARIANT_ID);
        assert_eq!(result.confidence, Confidence::Confirmed);
        assert!(!result.matched_evidence.is_empty());
    }

    #[test]
    fn probe_tolerates_non_json_lines_among_step_records() {
        let adapter = AntigravityAdapter::new();
        let fixture = format!(
            "garbage line\n{}",
            r#"{"step_index":0,"source":"USER_EXPLICIT","type":"USER_INPUT","status":"DONE","content":"hi"}"#
        );
        let result = adapter.probe(fixture.as_bytes()).unwrap();
        assert_eq!(result.confidence, Confidence::Confirmed);
        assert!(!result.unmatched_evidence.is_empty());
    }

    #[test]
    fn parse_maps_user_and_model_sources_and_skips_system() {
        let adapter = AntigravityAdapter::new();
        let mut sink = RecordingSink { events: Vec::new() };
        let report = adapter
            .parse(transcript_fixture().as_bytes(), &mut sink)
            .unwrap();
        assert_eq!(report.committed, 2);
        assert_eq!(sink.events.len(), 2);
        assert_eq!(sink.events[0].0, 0);
        assert_eq!(sink.events[0].1, "0");
        assert_eq!(sink.events[0].2, "user");
        assert_eq!(sink.events[0].3, "build the project");
        assert_eq!(sink.events[1].0, 1);
        assert_eq!(sink.events[1].1, "2");
        assert_eq!(sink.events[1].2, "assistant");
        assert_eq!(sink.events[1].3, "plan accepted");
        // SYSTEM steps never surface as user/assistant.
        assert!(sink.events.iter().all(|e| e.2 != "system"));
        // Identity is not fabricated: no native id, limitation in diagnostics.
        assert!(report.session_native_id.is_none());
        assert!(!report.diagnostics.is_empty());
    }

    #[test]
    fn parse_uses_thinking_when_content_is_empty() {
        let adapter = AntigravityAdapter::new();
        let fixture = r#"{"step_index":0,"source":"MODEL","type":"PLANNER_RESPONSE","status":"DONE","created_at":"2026-07-03T13:22:16Z","thinking":"internal reasoning only"}
"#;
        let mut sink = RecordingSink { events: Vec::new() };
        let report = adapter.parse(fixture.as_bytes(), &mut sink).unwrap();
        assert_eq!(report.committed, 1);
        assert_eq!(sink.events[0].2, "assistant");
        assert_eq!(sink.events[0].3, "internal reasoning only");
    }

    #[test]
    fn parse_skips_empty_steps() {
        let adapter = AntigravityAdapter::new();
        let fixture = r#"{"step_index":0,"source":"MODEL","type":"PLANNER_RESPONSE","status":"DONE"}
{"step_index":1,"source":"USER_EXPLICIT","type":"USER_INPUT","status":"DONE","content":"real request"}
"#;
        let mut sink = RecordingSink { events: Vec::new() };
        let report = adapter.parse(fixture.as_bytes(), &mut sink).unwrap();
        assert_eq!(report.committed, 1);
        assert_eq!(sink.events[0].3, "real request");
    }

    #[test]
    fn parse_skips_invalid_json_lines() {
        let adapter = AntigravityAdapter::new();
        let fixture = "not json\n{\"step_index\":0,\"source\":\"USER_EXPLICIT\",\"type\":\"USER_INPUT\",\"status\":\"DONE\",\"content\":\"ok\"}\n";
        let mut sink = RecordingSink { events: Vec::new() };
        let report = adapter.parse(fixture.as_bytes(), &mut sink).unwrap();
        assert_eq!(report.committed, 1);
        assert_eq!(report.skipped, 1);
        assert!(!report.diagnostics.is_empty());
    }

    #[test]
    fn parse_carries_valid_timestamps_and_drops_invalid_ones() {
        let adapter = AntigravityAdapter::new();
        let fixture = r#"{"step_index":0,"source":"USER_EXPLICIT","type":"USER_INPUT","status":"DONE","created_at":"not-a-timestamp","content":"first"}
{"step_index":1,"source":"MODEL","type":"PLANNER_RESPONSE","status":"DONE","created_at":"2026-07-03T13:22:16.5Z","content":"second"}
"#;
        let mut sink = RecordingSink { events: Vec::new() };
        adapter.parse(fixture.as_bytes(), &mut sink).unwrap();
        assert_eq!(sink.events[0].4, None);
        assert_eq!(sink.events[1].4.as_deref(), Some("2026-07-03T13:22:16.5Z"));
    }

    #[test]
    fn parse_emits_once_per_conversational_step() {
        let adapter = AntigravityAdapter::new();
        let mut sink = RecordingSink { events: Vec::new() };
        let report = adapter
            .parse(transcript_fixture().as_bytes(), &mut sink)
            .unwrap();
        // Exactly one event per committed message; no duplicates.
        assert_eq!(report.committed, sink.events.len());
    }
}
