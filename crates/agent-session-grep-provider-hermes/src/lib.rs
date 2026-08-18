//! Hermes agent provider adapter.
//!
//! Parses Hermes session transcripts from `~/.hermes/sessions/session_<id>.json`
//! (canonical format: full transcript + metadata; sibling `<id>.jsonl` files
//! hold only partial recent state and are ignored). The top level carries
//! `session_id`, `session_start`, and a `messages` array of
//! `{role, content, reasoning?, timestamp?, tool_call_id?, tool_calls?}`.
//!
//! Format evidence: hstry (MIT) `adapters/hermes/adapter.ts` @88b78b1. Field
//! shapes and the per-message extraction are adapted from hstry under MIT.

use agent_session_grep_ports::MetadataResolution;
use agent_session_grep_ports::{
    AdapterManifest, CanonicalEventSink, Confidence, MessageEvent, ParseReport, ProbeResult,
    ProviderAdapter, ProviderError, manifest_for,
};

/// Variant id surfaced in probe results.
const VARIANT_ID: &str = "hermes/session-json-v1";

/// Hermes agent adapter: parses `session_<id>.json` transcripts.
pub struct OpenHermesAdapter;

impl OpenHermesAdapter {
    pub fn new() -> Self {
        Self
    }
}

impl Default for OpenHermesAdapter {
    fn default() -> Self {
        Self::new()
    }
}

/// Minimal deserialization target for a Hermes session file.
///
/// Only fields needed for parse are modeled; unknown fields are silently
/// ignored (forward-compatible).
#[derive(serde::Deserialize)]
struct HermesSessionFile {
    #[serde(default)]
    session_id: Option<String>,
    #[serde(default)]
    session_start: Option<String>,
    #[serde(default)]
    messages: Option<Vec<HermesMessage>>,
}

#[derive(serde::Deserialize)]
struct HermesMessage {
    #[serde(default)]
    role: String,
    #[serde(default)]
    content: Option<String>,
    #[serde(default)]
    reasoning: Option<String>,
    /// Raw `timestamp`: string (ISO) or number (seconds or milliseconds).
    #[serde(default)]
    timestamp: Option<serde_json::Value>,
}

impl ProviderAdapter for OpenHermesAdapter {
    fn provider_id(&self) -> &str {
        "hermes"
    }

    fn manifest(&self) -> AdapterManifest {
        manifest_for(
            self.provider_id(),
            Some(1),
            &[
                "sibling <id>.jsonl files (partial recent state) are ignored; only session_<id>.json is parsed",
                "no byte spans (whole-file JSON); message timestamps fall back to session_start when absent",
            ],
        )
    }

    fn probe(&self, bytes: &[u8]) -> Result<ProbeResult, ProviderError> {
        let text = std::str::from_utf8(bytes)
            .map_err(|_| ProviderError::AmbiguousVariant("not valid UTF-8".into()))?;
        let text = text.strip_prefix('\u{feff}').unwrap_or(text).trim();
        if text.is_empty() {
            return Err(ProviderError::AmbiguousVariant(
                "empty input: nothing to probe".into(),
            ));
        }
        if !text.starts_with('{') {
            return Err(ProviderError::AmbiguousVariant(
                "input does not start with a JSON object".into(),
            ));
        }
        let value: serde_json::Value = serde_json::from_str(text)
            .map_err(|e| ProviderError::AmbiguousVariant(format!("not valid JSON: {e}")))?;

        let mut matched = Vec::new();
        let mut unmatched = Vec::new();

        // Empty transcript: reject outright (nothing to parse), even when a
        // `session_id` is present.
        if let Some(serde_json::Value::Array(items)) = value.get("messages")
            && items.is_empty()
        {
            return Err(ProviderError::AmbiguousVariant(
                "top-level `messages` array is empty".into(),
            ));
        }

        let messages_ok = match value.get("messages") {
            Some(serde_json::Value::Array(items)) => {
                let role_ok = items.iter().all(|m| m.get("role").is_some());
                matched.push(format!(
                    "top-level `messages` array with {} element(s)",
                    items.len()
                ));
                if !role_ok {
                    unmatched.push("some message elements lack a `role` field".into());
                }
                role_ok
            }
            Some(_) => {
                unmatched.push("top-level `messages` is not an array".into());
                false
            }
            None => false,
        };

        let session_id_ok = value
            .get("session_id")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|s| !s.trim().is_empty());

        if !messages_ok && !session_id_ok {
            return Err(ProviderError::AmbiguousVariant(
                "no Hermes `messages` array with role-bearing elements, nor a `session_id`".into(),
            ));
        }
        if session_id_ok {
            matched.push("top-level `session_id` present".into());
        }

        Ok(ProbeResult {
            variant_id: VARIANT_ID.to_string(),
            confidence: Confidence::Confirmed,
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
        let text = text.strip_prefix('\u{feff}').unwrap_or(text);
        let session: HermesSessionFile = serde_json::from_str(text).map_err(|e| {
            ProviderError::StructuralFatal(format!("not a Hermes session JSON: {e}"))
        })?;

        let mut report = ParseReport::default();
        let session_start = session.session_start.as_deref();

        if let Some(id) = session.session_id.as_deref()
            && !id.trim().is_empty()
        {
            let id = id.trim();
            report.session_native_id = Some(id.to_string());
            report.session_observation.provider_session_id =
                MetadataResolution::Resolved(id.to_string());
        }

        let mut seq: u32 = 0;
        if let Some(messages) = &session.messages {
            for (idx, msg) in messages.iter().enumerate() {
                let role = msg.role.as_str();
                if !matches!(role, "user" | "assistant") {
                    continue;
                }
                let Some(content) = msg.content.as_deref() else {
                    continue;
                };
                if content.trim().is_empty() {
                    continue;
                }
                let text = match msg.reasoning.as_deref().filter(|r| !r.trim().is_empty()) {
                    Some(reasoning) => format!("[thinking]\n{reasoning}\n[/thinking]\n{content}"),
                    None => content.to_string(),
                };
                let timestamp = msg
                    .timestamp
                    .as_ref()
                    .and_then(serde_json::Value::as_str)
                    .or(session_start);
                sink.emit_message(MessageEvent {
                    seq,
                    native_id: &format!("hermes-msg-{idx}"),
                    parent_native_id: None,
                    role,
                    text: &text,
                    timestamp,
                    is_sidechain: false,
                    span: None,
                })
                .map_err(|e| ProviderError::StructuralFatal(e.to_string()))?;
                seq += 1;
                report.committed += 1;
            }
        }

        Ok(report)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_matches_provider_matrix() {
        let adapter = OpenHermesAdapter::new();
        let manifest = adapter.manifest();
        assert_eq!(manifest.provider_id, adapter.provider_id());
        assert_eq!(manifest.supported_variants, vec![VARIANT_ID.to_string()]);
        assert_eq!(manifest.capabilities.provider_id, adapter.provider_id());
        assert_eq!(manifest.capabilities.variant_id, VARIANT_ID);
        assert!(manifest.last_certified_targets.is_empty());
        assert_eq!(manifest.fixture_revision, Some(1));
    }

    /// One captured emitted event, for assertions.
    #[derive(Debug)]
    struct Captured {
        seq: u32,
        native_id: String,
        role: String,
        text: String,
        timestamp: Option<String>,
    }

    #[derive(Default)]
    struct CapturingSink {
        events: Vec<Captured>,
    }

    impl CanonicalEventSink for CapturingSink {
        fn emit_message(
            &mut self,
            event: MessageEvent<'_>,
        ) -> agent_session_grep_ports::PortResult<()> {
            self.events.push(Captured {
                seq: event.seq,
                native_id: event.native_id.to_string(),
                role: event.role.to_string(),
                text: event.text.to_string(),
                timestamp: event.timestamp.map(str::to_string),
            });
            Ok(())
        }
    }

    /// Synthetic Hermes `session_<id>.json` fixture (no real data).
    fn hermes_fixture() -> &'static str {
        r#"{
          "session_id": "hermes-sess-7f3a",
          "model": "hermes-3",
          "base_url": "http://localhost:11434",
          "session_start": "2026-04-18T04:53:25.274422",
          "last_updated": "2026-04-18T05:12:00",
          "message_count": 6,
          "messages": [
            {"role": "system", "content": "You are a coding agent."},
            {"role": "user", "content": "hello world", "timestamp": "2026-04-18T04:53:26"},
            {"role": "assistant", "content": "", "reasoning": "only thinking"},
            {"role": "assistant", "content": "hi there", "reasoning": "thinking hard"},
            {"role": "tool", "content": "tool output", "tool_call_id": "tc-1", "tool_name": "read_file"},
            {"role": "user", "content": "next question"}
          ]
        }"#
    }

    #[test]
    fn probe_confirms_hermes_session_json() {
        let adapter = OpenHermesAdapter::new();
        let result = adapter.probe(hermes_fixture().as_bytes()).unwrap();
        assert_eq!(result.variant_id, VARIANT_ID);
        assert_eq!(result.confidence, Confidence::Confirmed);
        assert!(!result.matched_evidence.is_empty());
    }

    #[test]
    fn probe_rejects_plain_json() {
        let adapter = OpenHermesAdapter::new();
        let err = adapter.probe(br#"{"foo": 1, "bar": 2}"#).unwrap_err();
        assert!(matches!(err, ProviderError::AmbiguousVariant(_)));
    }

    #[test]
    fn probe_rejects_empty_bytes() {
        let adapter = OpenHermesAdapter::new();
        assert!(adapter.probe(b"").is_err());
    }

    #[test]
    fn probe_rejects_empty_messages_array() {
        let adapter = OpenHermesAdapter::new();
        let fixture = br#"{"session_id": "s1", "messages": []}"#;
        let err = adapter.probe(fixture).unwrap_err();
        assert!(matches!(err, ProviderError::AmbiguousVariant(_)));
    }

    #[test]
    fn probe_rejects_json_without_hermes_markers() {
        let adapter = OpenHermesAdapter::new();
        // A non-string `session_id` is not a Hermes marker.
        let fixture = br#"{"session_id": 42}"#;
        let err = adapter.probe(fixture).unwrap_err();
        assert!(matches!(err, ProviderError::AmbiguousVariant(_)));
    }

    #[test]
    fn parse_extracts_user_assistant_messages() {
        let adapter = OpenHermesAdapter::new();
        let mut sink = CapturingSink::default();
        let report = adapter
            .parse(hermes_fixture().as_bytes(), &mut sink)
            .unwrap();

        assert_eq!(report.committed, 3);
        assert_eq!(
            report.session_native_id.as_deref(),
            Some("hermes-sess-7f3a")
        );
        assert_eq!(
            report.session_observation.provider_session_id,
            MetadataResolution::Resolved("hermes-sess-7f3a".to_string())
        );

        let events = sink.events;
        assert_eq!(events.len(), 3);
        // System/tool/empty-content messages are skipped; native_id uses the
        // message index inside the messages array.
        assert_eq!(events[0].seq, 0);
        assert_eq!(events[0].native_id, "hermes-msg-1");
        assert_eq!(events[0].role, "user");
        assert_eq!(events[0].text, "hello world");
        assert_eq!(events[0].timestamp.as_deref(), Some("2026-04-18T04:53:26"));
        // Reasoning is kept as a [thinking] block; no own timestamp → fallback
        // to session_start.
        assert_eq!(events[1].seq, 1);
        assert_eq!(events[1].native_id, "hermes-msg-3");
        assert_eq!(events[1].role, "assistant");
        assert_eq!(
            events[1].text,
            "[thinking]\nthinking hard\n[/thinking]\nhi there"
        );
        assert_eq!(
            events[1].timestamp.as_deref(),
            Some("2026-04-18T04:53:25.274422")
        );
        assert_eq!(events[2].seq, 2);
        assert_eq!(events[2].native_id, "hermes-msg-5");
        assert_eq!(events[2].role, "user");
        assert_eq!(events[2].text, "next question");
        assert_eq!(
            events[2].timestamp.as_deref(),
            Some("2026-04-18T04:53:25.274422")
        );
    }

    #[test]
    fn parse_system_only_transcript_commits_nothing() {
        let adapter = OpenHermesAdapter::new();
        let fixture = r#"{
          "session_id": "hermes-sess-0",
          "messages": [
            {"role": "system", "content": "You are a coding agent."},
            {"role": "tool", "content": "tool output", "tool_call_id": "tc-1"}
          ]
        }"#;
        let mut sink = CapturingSink::default();
        let report = adapter.parse(fixture.as_bytes(), &mut sink).unwrap();
        assert_eq!(report.committed, 0);
        assert!(sink.events.is_empty());
    }

    #[test]
    fn parse_without_session_id_leaves_unresolved() {
        let adapter = OpenHermesAdapter::new();
        let fixture = r#"{
          "messages": [
            {"role": "user", "content": "hello"}
          ]
        }"#;
        let mut sink = CapturingSink::default();
        let report = adapter.parse(fixture.as_bytes(), &mut sink).unwrap();
        assert_eq!(report.committed, 1);
        assert_eq!(report.session_native_id, None);
        assert_eq!(
            report.session_observation.provider_session_id,
            MetadataResolution::Missing
        );
    }
}
