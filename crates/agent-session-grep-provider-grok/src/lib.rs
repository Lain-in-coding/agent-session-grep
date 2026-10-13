//! Grok Build provider adapter.
//!
//! Parses the ACP `session/update` stream (`updates.jsonl`) that Grok Build
//! writes alongside a `summary.json` per session. Each line is a JSON-RPC-like
//! notification whose `params.update.sessionUpdate` discriminator selects a
//! chunk kind (`user_message_chunk` / `agent_message_chunk` / `rewind_marker`).
//!
//! Agent message chunks are grouped by `params._meta.promptId`; user message
//! chunks by `update._meta.promptIndex`. A `rewind_marker` truncates the
//! reconstructed message list to the target prompt index.
//!
//! Format evidence: fast-resume (MIT) `src/adapters/grok.rs`. The chunk-grouping
//! approach is adapted from fast-resume under its MIT license.

use agent_session_grep_ports::MetadataResolution;
use agent_session_grep_ports::{
    AdapterManifest, CanonicalEventSink, Confidence, MessageEvent, ParseReport, ProbeResult,
    ProviderAdapter, ProviderError, manifest_for,
};

/// Variant id surfaced in probe results.
const VARIANT_ID: &str = "grok-build/acp-updates-v1";

/// Number of non-blank lines to sample during probe (bounded, RFC-0002 §7).
const SAMPLE_LINE_LIMIT: usize = 8;

/// Grok Build adapter: parses `updates.jsonl` (ACP session/update stream).
///
/// `summary.json` is not read here because the port contract delivers a single
/// byte stream. Session identity falls back to the first record that carries a
/// usable id; when none is found the report leaves it `None` and the caller
/// (discovery layer) may supply a path-derived id.
pub struct GrokBuildAdapter;

impl GrokBuildAdapter {
    pub fn new() -> Self {
        Self
    }
}

impl Default for GrokBuildAdapter {
    fn default() -> Self {
        Self::new()
    }
}

/// Minimal deserialization targets for the ACP update record.
///
/// Only the fields needed for probe/parse are modeled; unknown fields are
/// silently ignored (forward-compatible). The full structure is accessed via
/// `serde_json::Value` in the parse path for resilience.
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct UpdateRecord {
    #[serde(default)]
    #[allow(dead_code)]
    timestamp: Option<String>,
    #[serde(default)]
    params: Option<UpdateParams>,
}

#[derive(serde::Deserialize, Default, Clone)]
#[serde(rename_all = "camelCase")]
struct UpdateParams {
    #[serde(default)]
    update: Option<UpdateBody>,
    // The ACP `session/update` payload nests meta under `_meta` (leading
    // underscore); `rename_all` alone would not map `meta` → `_meta`, so the
    // explicit rename is required for promptId/promptIndex to be observed.
    #[serde(default, rename = "_meta")]
    meta: Option<UpdateMeta>,
}

#[derive(serde::Deserialize, Default, Clone)]
#[serde(rename_all = "camelCase")]
struct UpdateBody {
    #[serde(default, rename = "sessionUpdate")]
    session_update: Option<String>,
    #[serde(default)]
    content: Option<serde_json::Value>,
    #[serde(default, rename = "targetPromptIndex")]
    target_prompt_index: Option<u64>,
    #[serde(default, rename = "target_prompt_index")]
    target_prompt_index_snake: Option<u64>,
}

#[derive(serde::Deserialize, Default, Clone)]
#[serde(rename_all = "camelCase")]
struct UpdateMeta {
    #[serde(default, rename = "promptIndex")]
    prompt_index: Option<u64>,
    #[serde(default, rename = "promptId")]
    prompt_id: Option<String>,
}

impl ProviderAdapter for GrokBuildAdapter {
    fn provider_id(&self) -> &str {
        "grok-build"
    }

    fn manifest(&self) -> AdapterManifest {
        manifest_for(
            self.provider_id(),
            Some(1),
            &[
                "chunk grouping reconstructs roles; no per-message native ids (ids are derived, not native)",
                "per-message timestamps are not extracted (always None)",
                "session identity falls back to the first ACP promptId seen, not a durable session id",
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
        let mut update_records = 0usize;
        let mut chunk_records = 0usize;

        for &(line_no, line) in &sample {
            match serde_json::from_str::<serde_json::Value>(line) {
                Ok(v) => {
                    json_lines += 1;
                    let su = v
                        .pointer("/params/update/sessionUpdate")
                        .and_then(serde_json::Value::as_str);
                    if su.is_some() {
                        update_records += 1;
                    }
                    if matches!(su, Some("user_message_chunk" | "agent_message_chunk")) {
                        chunk_records += 1;
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

        // Grok Build's ACP format is structurally distinct from Claude/Codex
        // JSONL: every record carries params.update.sessionUpdate. If no ACP
        // sessionUpdate record is present, refuse rather than returning Low —
        // Low would compete with other adapters' Low and cause ambiguous
        // selection on non-Grok JSONL files.
        if update_records == 0 {
            return Err(ProviderError::AmbiguousVariant(
                "no ACP sessionUpdate records found in sampled lines".into(),
            ));
        }

        let confidence = if chunk_records > 0 {
            matched.push(format!(
                "{chunk_records} ACP message chunks (user/agent) found"
            ));
            Confidence::Confirmed
        } else {
            matched.push(format!("{update_records} ACP sessionUpdate records found"));
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
        // 流式逐行读取：输入不再整体驻留内存（RFC-0002 §7）。注意本 variant
        // 的 chunked message 重建天然要按消息累积文本，见 manifest 已知限制。
        let mut lines = agent_session_grep_ports::BoundedLineReader::new(
            source,
            agent_session_grep_ports::STREAM_RECORD_MAX_BYTES,
        )
        .map_err(|e| ProviderError::Io(e.to_string()))?;

        let mut report = ParseReport::default();
        let mut seq: u32 = 0;

        // Reconstructed messages: (is_user, text). Chunks accumulate into these.
        let mut messages: Vec<(bool, String)> = Vec::new();
        let mut user_message_indices: Vec<usize> = Vec::new();
        let mut pending_user: Option<(Option<u64>, usize)> = None;
        let mut pending_agent: Option<(String, usize)> = None;
        let mut seen_prompt_index = false;
        // Track byte spans per reconstructed message for evidence.
        // message_spans tracks the last-seen span per message (for future
        // multi-span evidence); currently only first_spans is emitted.
        #[allow(unused_mut)]
        let mut message_spans: Vec<Option<(u64, u64)>> = Vec::new();
        // First span seen for each message (evidence start).
        let mut message_first_spans: Vec<Option<(u64, u64)>> = Vec::new();
        // Session id candidates extracted from records (rare in updates.jsonl).
        let mut session_ids: Vec<String> = Vec::new();

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

            let record: UpdateRecord = match serde_json::from_str(parse_line) {
                Ok(r) => r,
                Err(e) => {
                    report.skipped += 1;
                    report
                        .diagnostics
                        .push(format!("line {}: invalid JSON, skipped ({e})", line_no + 1));
                    continue;
                }
            };

            // Collect timestamp for session observation (not per-message yet).
            // Timestamp enrichment is a future hook; left intentionally absent.

            let UpdateParams { update, meta } = record.params.unwrap_or_default();
            let update = update.unwrap_or_default();
            let meta = meta.unwrap_or_default();

            let su = update.session_update.clone().unwrap_or_default();
            let content = update.content.clone().unwrap_or(serde_json::Value::Null);
            let target = update
                .target_prompt_index
                .or(update.target_prompt_index_snake);
            let prompt_index = meta.prompt_index;
            let prompt_id = meta.prompt_id.unwrap_or_default();
            match su.as_str() {
                "user_message_chunk" => {
                    pending_agent = None;
                    // Skip bash-command meta chunks (tool activity, not conversational).
                    if content.pointer("/_meta/bashCommand").is_some() {
                        pending_user = None;
                        continue;
                    }
                    let text = grok_content_text(&content);
                    if text.is_empty() {
                        continue;
                    }
                    if prompt_index.is_some() {
                        seen_prompt_index = true;
                    }
                    let counts_as_user = !seen_prompt_index || prompt_index.is_some();
                    if !counts_as_user {
                        pending_user = None;
                        continue;
                    }
                    if let Some((pending_idx, msg_idx)) = &pending_user
                        && pending_idx == &prompt_index
                        && let Some((true, current)) = messages.get_mut(*msg_idx)
                    {
                        current.push_str(&text);
                        continue;
                    }
                    let msg_idx = messages.len();
                    user_message_indices.push(msg_idx);
                    messages.push((true, text));
                    message_spans.push(Some((start, end)));
                    message_first_spans.push(Some((start, end)));
                    pending_user = Some((prompt_index, msg_idx));
                }
                "agent_message_chunk" => {
                    pending_user = None;
                    let text = grok_content_text(&content);
                    if text.trim().is_empty() {
                        continue;
                    }
                    if let Some((pending_id, msg_idx)) = &pending_agent
                        && pending_id == &prompt_id
                        && let Some((false, current)) = messages.get_mut(*msg_idx)
                    {
                        current.push_str(&text);
                        continue;
                    }
                    let msg_idx = messages.len();
                    messages.push((false, text));
                    message_spans.push(Some((start, end)));
                    message_first_spans.push(Some((start, end)));
                    pending_agent = Some((prompt_id.clone(), msg_idx));
                }
                "rewind_marker" => {
                    if let Some(target) = target
                        && let Ok(target) = usize::try_from(target)
                        && let Some(msg_idx) = user_message_indices.get(target).copied()
                    {
                        messages.truncate(msg_idx);
                        user_message_indices.truncate(target);
                        message_spans.truncate(msg_idx);
                        message_first_spans.truncate(msg_idx);
                        pending_user = None;
                        pending_agent = None;
                    }
                }
                _ => {
                    // Unknown sessionUpdate kind or non-update record: skip.
                }
            }

            // Collect any session id found in params (rare for updates.jsonl).
            if !prompt_id.is_empty() && !session_ids.iter().any(|s| s == &prompt_id) {
                session_ids.push(prompt_id.clone());
            }
        }

        // Emit reconstructed messages in order.
        // `native_id` is empty: grok transcripts carry no durable per-message
        // id, so the composition root derives a document-scoped id instead of
        // adopting a synthetic `<provider>-msg-{seq}` that would collide
        // across documents.
        for (idx, (is_user, text)) in messages.iter().enumerate() {
            let role = if *is_user { "user" } else { "assistant" };
            let span = message_first_spans.get(idx).copied().flatten();
            sink.emit_message(MessageEvent {
                session: None,
                seq,
                native_id: "",
                parent_native_id: None,
                role,
                text,
                timestamp: None,
                is_sidechain: false,
                span,
            })
            .map_err(|e| ProviderError::StructuralFatal(e.to_string()))?;
            seq += 1;
            report.committed += 1;
        }

        // Session identity: prefer first collected id; otherwise leave None
        // (discovery layer may supply a path-derived id).
        if let Some(first) = session_ids.first() {
            report.session_native_id = Some(first.clone());
            report.session_observation.provider_session_id =
                MetadataResolution::Resolved(first.clone());
        }
        if session_ids.len() > 1 {
            report.session_observation.multi_session = true;
            report.session_observation.provider_session_id = MetadataResolution::Ambiguous;
            report.diagnostics.push(format!(
                "文件包含 {} 个不同 id——单文件=单会话，归属保持首个",
                session_ids.len()
            ));
        }

        Ok(report)
    }
}

/// Extract plain text from a Grok content value.
///
/// Grok ACP uses all three content shapes in documented/reference transcripts:
/// a bare string, an array of content blocks, and a single `{type:"text",text:…}`
/// object. The object form is common in fast-resume/Recall fixtures. Non-string,
/// non-array/object values yield empty text.
fn grok_content_text(content: &serde_json::Value) -> String {
    match content {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Array(blocks) => {
            let mut buf = String::new();
            for block in blocks {
                if let Some(t) = block.get("text").and_then(serde_json::Value::as_str) {
                    if !buf.is_empty() {
                        buf.push('\n');
                    }
                    buf.push_str(t);
                }
            }
            buf
        }
        serde_json::Value::Object(object) => object
            .get("text")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_string(),
        _ => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_matches_provider_matrix() {
        let adapter = GrokBuildAdapter::new();
        let manifest = adapter.manifest();
        assert_eq!(manifest.provider_id, adapter.provider_id());
        assert_eq!(manifest.supported_variants, vec![VARIANT_ID.to_string()]);
        assert_eq!(manifest.capabilities.provider_id, adapter.provider_id());
        assert_eq!(manifest.capabilities.variant_id, VARIANT_ID);
        assert!(manifest.last_certified_targets.is_empty());
        assert_eq!(manifest.fixture_revision, Some(1));
    }

    #[test]
    fn probe_rejects_empty_input() {
        let adapter = GrokBuildAdapter::new();
        let result = adapter.probe(b"");
        assert!(result.is_err());
    }

    #[test]
    fn probe_confirms_acp_update_stream() {
        let adapter = GrokBuildAdapter::new();
        let fixture = r#"{"timestamp":"2026-01-01T00:00:00Z","params":{"update":{"sessionUpdate":"user_message_chunk","content":"hi"}}}
{"timestamp":"2026-01-01T00:00:01Z","params":{"update":{"sessionUpdate":"agent_message_chunk","content":"hello"}}}
"#;
        let result = adapter.probe(fixture.as_bytes()).unwrap();
        assert_eq!(result.variant_id, VARIANT_ID);
        assert_eq!(result.confidence, Confidence::Confirmed);
    }

    #[test]
    fn probe_rejects_non_acp_jsonl() {
        let adapter = GrokBuildAdapter::new();
        let fixture = "{\"foo\":1}\n{\"bar\":2}\n";
        // Non-ACP JSONL must be refused (not Low) to avoid competing with
        // other adapters and causing ambiguous selection.
        assert!(adapter.probe(fixture.as_bytes()).is_err());
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
    fn parse_groups_chunks_into_messages() {
        let adapter = GrokBuildAdapter::new();
        let fixture = r#"{"timestamp":"2026-01-01T00:00:00Z","params":{"update":{"sessionUpdate":"user_message_chunk","content":"hello "},"_meta":{"promptIndex":0}}}
{"timestamp":"2026-01-01T00:00:00Z","params":{"update":{"sessionUpdate":"user_message_chunk","content":"world"},"_meta":{"promptIndex":0}}}
{"timestamp":"2026-01-01T00:00:01Z","params":{"update":{"sessionUpdate":"agent_message_chunk","content":"hi there"},"_meta":{"promptId":"p1"}}}
"#;
        let mut sink = CountSink { count: 0 };
        let report = adapter.parse(fixture.as_bytes(), &mut sink).unwrap();
        assert_eq!(sink.count, 2);
        assert_eq!(report.committed, 2);
    }

    #[test]
    fn parse_handles_rewind_marker() {
        let adapter = GrokBuildAdapter::new();
        let fixture = r#"{"params":{"update":{"sessionUpdate":"user_message_chunk","content":"msg0"},"_meta":{"promptIndex":0}}}
{"params":{"update":{"sessionUpdate":"user_message_chunk","content":"msg1"},"_meta":{"promptIndex":1}}}
{"params":{"update":{"sessionUpdate":"rewind_marker","targetPromptIndex":0}}}
{"params":{"update":{"sessionUpdate":"agent_message_chunk","content":"after rewind"},"_meta":{"promptId":"p1"}}}
"#;
        let mut sink = CountSink { count: 0 };
        let report = adapter.parse(fixture.as_bytes(), &mut sink).unwrap();
        // rewind to prompt index 0 discards msg0 and everything after,
        // then agent message → 1 total
        assert_eq!(sink.count, 1);
        assert_eq!(report.committed, 1);
    }

    #[test]
    fn oversized_rewind_target_cannot_wrap_to_an_existing_prompt() {
        for target in [u64::from(u32::MAX) + 1, u64::MAX] {
            let fixture = format!(
                "{{\"params\":{{\"update\":{{\"sessionUpdate\":\"user_message_chunk\",\"content\":\"retained\"}},\"_meta\":{{\"promptIndex\":0}}}}}}\n\
                 {{\"params\":{{\"update\":{{\"sessionUpdate\":\"rewind_marker\",\"targetPromptIndex\":{target}}}}}}}\n"
            );
            let mut sink = TextSink { texts: vec![] };
            let report = GrokBuildAdapter::new()
                .parse(fixture.as_bytes(), &mut sink)
                .unwrap();
            assert_eq!(sink.texts, vec!["retained"]);
            assert_eq!(report.committed, 1);
        }
    }

    #[test]
    fn parse_skips_invalid_json_lines() {
        let adapter = GrokBuildAdapter::new();
        let fixture = "not json\n{\"params\":{\"update\":{\"sessionUpdate\":\"user_message_chunk\",\"content\":\"ok\"}}}\n";
        let mut sink = CountSink { count: 0 };
        let report = adapter.parse(fixture.as_bytes(), &mut sink).unwrap();
        assert_eq!(report.committed, 1);
        assert_eq!(report.skipped, 1);
        assert!(!report.diagnostics.is_empty());
    }

    #[test]
    fn parse_array_content_blocks_concatenated() {
        let adapter = GrokBuildAdapter::new();
        let fixture = r#"{"params":{"update":{"sessionUpdate":"agent_message_chunk","content":[{"text":"part1"},{"text":"part2"}]},"_meta":{"promptId":"p1"}}}
"#;
        let mut sink = CountSink { count: 0 };
        let report = adapter.parse(fixture.as_bytes(), &mut sink).unwrap();
        assert_eq!(report.committed, 1);
    }

    struct TextSink {
        texts: Vec<String>,
    }
    impl CanonicalEventSink for TextSink {
        fn emit_message(
            &mut self,
            event: MessageEvent<'_>,
        ) -> agent_session_grep_ports::PortResult<()> {
            self.texts.push(event.text.to_string());
            Ok(())
        }
    }

    #[test]
    fn parse_object_content_shape_is_not_dropped() {
        // Reference ACP fixtures (fast-resume/Recall) encode a chunk as one
        // `{type:"text",text:…}` object rather than a bare string or array. Before
        // the object branch in `grok_content_text`, both user and assistant chunks
        // became empty, hit `continue`, and vanished from the index.
        let adapter = GrokBuildAdapter::new();
        let fixture = r#"{"params":{"update":{"sessionUpdate":"user_message_chunk","content":{"type":"text","text":"object-shaped user"}},"_meta":{"promptIndex":0}}}
{"params":{"update":{"sessionUpdate":"agent_message_chunk","content":{"type":"text","text":"object-shaped assistant"}},"_meta":{"promptId":"p1"}}}
"#;
        let mut sink = TextSink { texts: vec![] };
        let report = adapter.parse(fixture.as_bytes(), &mut sink).unwrap();
        assert_eq!(report.committed, 2);
        assert_eq!(
            sink.texts,
            vec![
                "object-shaped user".to_string(),
                "object-shaped assistant".to_string(),
            ]
        );
    }

    #[test]
    fn object_content_shape_keeps_empty_object_non_message() {
        // An object without a string `text` still carries no searchable prose;
        // preserve the existing empty-content skip rather than stringifying the
        // object or inventing a body.
        assert!(grok_content_text(&serde_json::json!({"type": "image"})).is_empty());
    }

    #[test]
    fn parse_passes_noise_shaped_user_text_through_verbatim() {
        // 钉住测试：Grok ACP 流没有 system-reminder / AGENTS.md / 环境上下文等
        // 注入概念（本格式唯一的 user-chunk 内容过滤是 bashCommand 工具元
        // chunk，过滤依据是 `_meta` 结构而非文本形状）。形似噪声的 user 文本
        // 必须逐字透传，防止将来把别家格式的过滤规则盲目搬来造成 silent drift。
        let adapter = GrokBuildAdapter::new();
        let fixture = r##"{"params":{"update":{"sessionUpdate":"user_message_chunk","content":"<system-reminder>reminder text</system-reminder>"},"_meta":{"promptIndex":0}}}
{"params":{"update":{"sessionUpdate":"user_message_chunk","content":"# AGENTS.md instructions"},"_meta":{"promptIndex":1}}}
"##;
        let mut sink = TextSink { texts: vec![] };
        let report = adapter.parse(fixture.as_bytes(), &mut sink).unwrap();
        assert_eq!(report.committed, 2);
        assert_eq!(report.skipped, 0);
        assert_eq!(
            sink.texts,
            vec![
                "<system-reminder>reminder text</system-reminder>".to_string(),
                "# AGENTS.md instructions".to_string(),
            ]
        );
    }
}
