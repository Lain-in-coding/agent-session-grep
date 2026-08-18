//! Kimi Code provider adapter.
//!
//! Parses Kimi's wire.jsonl format: each line carries a `type` discriminator.
//! `context.append_message` records wrap `message.role` (user/assistant) and
//! `message.content`. `context.append_loop_event` records carry step/tool
//! events (step.begin/content.part/tool.call/tool.result/step.end) — this
//! initial implementation handles append_message; loop events are deferred.
//!
//! Format evidence: fast-resume (MIT) `src/adapters/kimi.rs`. The message
//! extraction is adapted from fast-resume under its MIT license.

use agent_session_grep_ports::MetadataResolution;
use agent_session_grep_ports::{
    AdapterManifest, CanonicalEventSink, Confidence, MessageEvent, ParseReport, ProbeResult,
    ProviderAdapter, ProviderError, manifest_for,
};

/// Variant id surfaced in probe results.
const VARIANT_ID: &str = "kimi-code/wire-jsonl-v1";

/// Number of non-blank lines to sample during probe (bounded, RFC-0002 §7).
const SAMPLE_LINE_LIMIT: usize = 8;

/// Kimi Code adapter: parses wire.jsonl with type-discriminated records.
pub struct KimiCodeAdapter;

impl KimiCodeAdapter {
    pub fn new() -> Self {
        Self
    }
}

impl Default for KimiCodeAdapter {
    fn default() -> Self {
        Self::new()
    }
}

/// Minimal deserialization target for a Kimi wire.jsonl record.
#[derive(serde::Deserialize)]
struct WireRecord {
    #[serde(default)]
    r#type: String,
    #[serde(default)]
    message: Option<WireMessage>,
}

#[derive(serde::Deserialize)]
struct WireMessage {
    #[serde(default)]
    role: String,
    #[serde(default)]
    content: Option<serde_json::Value>,
}

impl ProviderAdapter for KimiCodeAdapter {
    fn provider_id(&self) -> &str {
        "kimi-code"
    }

    fn manifest(&self) -> AdapterManifest {
        manifest_for(
            self.provider_id(),
            Some(1),
            &[
                "context.append_loop_event records (step/tool events) are not yet parsed",
                "session id is rarely carried in wire.jsonl; session_native_id is usually left unset",
                "per-message timestamps are not extracted",
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
        let mut append_message_records = 0usize;
        let mut conversational = 0usize;

        for &(line_no, line) in &sample {
            match serde_json::from_str::<serde_json::Value>(line) {
                Ok(v) => {
                    json_lines += 1;
                    let t = v
                        .get("type")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("");
                    if t == "context.append_message" {
                        append_message_records += 1;
                        let role = v
                            .pointer("/message/role")
                            .and_then(serde_json::Value::as_str)
                            .unwrap_or("");
                        if matches!(role, "user" | "assistant") {
                            conversational += 1;
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

        // Kimi wire.jsonl is distinct: context.append_message / context.append_loop_event.
        // Refuse if no Kimi-specific type markers present.
        if append_message_records == 0 {
            return Err(ProviderError::AmbiguousVariant(
                "no Kimi context.append_message records found in sampled lines".into(),
            ));
        }

        let confidence = if conversational > 0 {
            matched.push(format!(
                "{append_message_records} append_message records, {conversational} conversational"
            ));
            Confidence::Confirmed
        } else {
            matched.push(format!(
                "{append_message_records} append_message records found"
            ));
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

            let rec: WireRecord = match serde_json::from_str(parse_line) {
                Ok(r) => r,
                Err(e) => {
                    report.skipped += 1;
                    report
                        .diagnostics
                        .push(format!("line {}: invalid JSON, skipped ({e})", line_no + 1));
                    continue;
                }
            };

            // Only handle context.append_message; loop events deferred.
            if rec.r#type != "context.append_message" {
                continue;
            }

            let Some(msg) = &rec.message else {
                report.skipped += 1;
                continue;
            };
            let role = msg.role.as_str();
            if !matches!(role, "user" | "assistant") {
                continue;
            }
            let content = msg.content.as_ref().unwrap_or(&serde_json::Value::Null);
            let text = kimi_content_texts(content);
            if text.trim().is_empty() {
                continue;
            }

            sink.emit_message(MessageEvent {
                seq,
                native_id: &format!("kimi-msg-{seq}"),
                parent_native_id: None,
                role,
                text: &text,
                timestamp: None,
                is_sidechain: false,
                span: Some((start, end)),
            })
            .map_err(|e| ProviderError::StructuralFatal(e.to_string()))?;
            seq += 1;
            report.committed += 1;

            // Session identity: Kimi wire.jsonl rarely carries session id;
            // left None (discovery layer may supply path-derived id).
            if report.session_observation.provider_session_id == MetadataResolution::Missing {
                let _ = &report.session_observation;
            }
        }

        Ok(report)
    }
}

/// Extract text from Kimi message content.
///
/// Content can be a string or an array of content parts with `text` fields.
fn kimi_content_texts(content: &serde_json::Value) -> String {
    match content {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Array(parts) => {
            let mut buf = String::new();
            for part in parts {
                if let Some(t) = part.get("text").and_then(serde_json::Value::as_str) {
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
        let adapter = KimiCodeAdapter::new();
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
        let adapter = KimiCodeAdapter::new();
        assert!(adapter.probe(b"").is_err());
    }

    #[test]
    fn probe_confirms_kimi_wire_jsonl() {
        let adapter = KimiCodeAdapter::new();
        let fixture = r#"{"type":"context.append_message","message":{"role":"user","content":"hello"}}
{"type":"context.append_message","message":{"role":"assistant","content":"hi there"}}
"#;
        let result = adapter.probe(fixture.as_bytes()).unwrap();
        assert_eq!(result.variant_id, VARIANT_ID);
        assert_eq!(result.confidence, Confidence::Confirmed);
    }

    #[test]
    fn probe_rejects_non_kimi_jsonl() {
        let adapter = KimiCodeAdapter::new();
        let fixture = "{\"foo\":1}\n{\"bar\":2}\n";
        assert!(adapter.probe(fixture.as_bytes()).is_err());
    }

    #[test]
    fn parse_extracts_messages() {
        let adapter = KimiCodeAdapter::new();
        let fixture = r#"{"type":"context.append_message","message":{"role":"user","content":"hello world"}}
{"type":"context.append_message","message":{"role":"assistant","content":"hi there"}}
"#;
        let mut sink = CountSink { count: 0 };
        let report = adapter.parse(fixture.as_bytes(), &mut sink).unwrap();
        assert_eq!(sink.count, 2);
        assert_eq!(report.committed, 2);
    }

    #[test]
    fn parse_skips_loop_events() {
        let adapter = KimiCodeAdapter::new();
        let fixture = r#"{"type":"context.append_loop_event","event":{"type":"step.begin","uuid":"s1"}}
{"type":"context.append_message","message":{"role":"user","content":"real msg"}}
"#;
        let mut sink = CountSink { count: 0 };
        let report = adapter.parse(fixture.as_bytes(), &mut sink).unwrap();
        assert_eq!(report.committed, 1);
    }

    #[test]
    fn parse_skips_invalid_json() {
        let adapter = KimiCodeAdapter::new();
        let fixture = "not json\n{\"type\":\"context.append_message\",\"message\":{\"role\":\"user\",\"content\":\"ok\"}}\n";
        let mut sink = CountSink { count: 0 };
        let report = adapter.parse(fixture.as_bytes(), &mut sink).unwrap();
        assert_eq!(report.committed, 1);
        assert_eq!(report.skipped, 1);
    }

    #[test]
    fn parse_array_content_parts() {
        let adapter = KimiCodeAdapter::new();
        let fixture = r#"{"type":"context.append_message","message":{"role":"assistant","content":[{"text":"part1"},{"text":"part2"}]}}
"#;
        let mut sink = CountSink { count: 0 };
        let report = adapter.parse(fixture.as_bytes(), &mut sink).unwrap();
        assert_eq!(report.committed, 1);
    }

    #[test]
    fn parse_skips_non_conversational_roles() {
        let adapter = KimiCodeAdapter::new();
        let fixture = r#"{"type":"context.append_message","message":{"role":"system","content":"system msg"}}
{"type":"context.append_message","message":{"role":"user","content":"real msg"}}
"#;
        let mut sink = CountSink { count: 0 };
        let report = adapter.parse(fixture.as_bytes(), &mut sink).unwrap();
        assert_eq!(report.committed, 1);
    }
}
