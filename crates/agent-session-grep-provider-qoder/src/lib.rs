//! Qoder coding agent provider adapter.
//!
//! Parses Qoder's transcript JSONL format: each line carries a `type`
//! discriminator that doubles as the conversational role for chat records.
//! `type: "session_meta"` is the header (carries session identity/`cwd`);
//! `type: "user"` / `type: "assistant"` are conversational messages with a
//! `message.content` body; `progress` / `tool_use` / `tool_result` are
//! non-conversational and skipped by the canonical adapter.
//!
//! Format evidence: ctx (Apache-2.0) `provider-support-matrix.json` — source
//! root `~/.qoder/projects/<project>/transcript/*.jsonl`, record types
//! `session_meta`/`user`/`assistant`/`progress`/`tool_use`/`tool_result`.
//! Identity fields are extracted from `session_meta` (fixture-derived;
//! `session_id`/`cwd` keys are matched leniently).
//!
//! # Scope: Qoder writes history to two unrelated surfaces
//!
//! This adapter covers **only** the transcript JSONL tree above. Qoder's
//! Electron IDE keeps a second, entirely different history store — a SQLite DB
//! at `%APPDATA%/Qoder/SharedClientCache/cache/db/local.db` with
//! `chat_session(session_id, session_title, project_uri, gmt_create, …)`,
//! `chat_message(id, session_id, request_id, role, content, …)`, and
//! `chat_record(request_id, session_id, question, answer, summary, …)`. That
//! schema is the Lingma one (Qoder is Alibaba's rebrand of the Lingma product
//! line, and `ctx` imports it under its `lingma_sqlite` source format from
//! `~/.lingma/vscode/sharedClientCache/cache/db/local.db`); `ctx` likewise
//! keeps the two rows separate and records "does not parse Qoder VS Code /
//! Electron state databases" against its Qoder JSONL row.
//!
//! The split is why `qoder` has no [`PROVIDER_DISCOVERY_ROOTS`] entry: a
//! discovery root is a (root, extension) pair, and the two surfaces share
//! neither. Registering the JSONL root on a machine that only has the SQLite
//! store would make the scan *complete and empty*, which is precisely the
//! shape that tombstones an entire provider's index. Adding SQLite support
//! means a second variant (`qoder/sqlite-v1`, modeled on `opencode/sqlite-v1`)
//! plus its own root — not a widened extension filter on this one.
//!
//! [`PROVIDER_DISCOVERY_ROOTS`]: ../../agent_session_grep_cli/index.html

use agent_session_grep_ports::MetadataResolution;
use agent_session_grep_ports::{
    AdapterManifest, CanonicalEventSink, Confidence, MessageEvent, ParseReport, ProbeResult,
    ProviderAdapter, ProviderError, manifest_for,
};

/// Variant id surfaced in probe results.
const VARIANT_ID: &str = "qoder/transcript-jsonl-v1";

/// Number of non-blank lines to sample during probe (bounded, RFC-0002 §7).
const SAMPLE_LINE_LIMIT: usize = 8;

/// Qoder coding agent adapter: parses transcript JSONL with `type`-discriminated
/// records where the chat record type is itself the role.
pub struct QoderAdapter;

impl QoderAdapter {
    pub fn new() -> Self {
        Self
    }
}

impl Default for QoderAdapter {
    fn default() -> Self {
        Self::new()
    }
}

/// Minimal deserialization target for a Qoder JSONL record.
///
/// Only fields needed for probe/parse are modeled; unknown fields are silently
/// ignored (forward-compatible). `type` is the discriminator; `message.content`
/// carries the chat body; `session_meta` carries identity fields as an opaque
/// object so unknown key shapes don't block parsing.
#[derive(serde::Deserialize)]
struct QoderRecord {
    #[serde(default, rename = "type")]
    r#type: String,
    #[serde(default)]
    message: Option<QoderMessage>,
    /// `session_meta` record body (identity fields probed leniently).
    #[serde(default)]
    session_meta: Option<serde_json::Value>,
    /// Some Qoder records carry a top-level `timestamp`.
    #[serde(default)]
    timestamp: Option<String>,
    /// Session id may appear at top level of `session_meta`.
    #[serde(default)]
    session_id: Option<String>,
    /// Working directory may appear at top level of `session_meta`.
    #[serde(default)]
    cwd: Option<String>,
}

#[derive(serde::Deserialize)]
struct QoderMessage {
    #[serde(default)]
    #[allow(dead_code)]
    role: String,
    #[serde(default)]
    content: Option<serde_json::Value>,
    #[serde(default)]
    timestamp: Option<String>,
}

impl ProviderAdapter for QoderAdapter {
    fn provider_id(&self) -> &str {
        "qoder"
    }

    fn manifest(&self) -> AdapterManifest {
        manifest_for(
            self.provider_id(),
            Some(1),
            &[
                "identity fields are matched leniently from session_meta (session_id/cwd)",
                "non-conversational records (progress/tool_use/tool_result) are skipped",
                "only the transcript JSONL surface is parsed; the Qoder IDE's Electron \
                 SQLite store (chat_session/chat_message/chat_record) is a different \
                 format and is not read",
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
        let mut session_meta = 0usize;
        let mut conversational = 0usize;

        let mut codex_envelopes = 0usize;
        for &(line_no, line) in &sample {
            match serde_json::from_str::<serde_json::Value>(line) {
                Ok(v) => {
                    json_lines += 1;
                    let t = v
                        .get("type")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("");
                    // `session_meta` 这个 type 名并非 Qoder 独有：Codex rollout 的
                    // 每条记录都是 `{timestamp, type, payload}` 封套，其首行同样是
                    // 顶层 `type:"session_meta"`。Qoder 的 session_meta 把身份字段放
                    // 在顶层或 `session_meta` 对象里，从不带 `payload`——因此
                    // `payload` 的存在就是"这是 Codex 封套而非 Qoder 头"的判别位。
                    // 不区分会让 Qoder 对 Codex rollout 报 High：codex 自身遇到容忍
                    // 范围内的坏行时会从 Confirmed 降到 High，两者并列即触发
                    // `select_and_stage_source` 的 tie 分支拒绝整个源。
                    let codex_enveloped = v.get("payload").is_some();
                    match t {
                        "session_meta" if codex_enveloped => codex_envelopes += 1,
                        "session_meta" => session_meta += 1,
                        "user" | "assistant" => {
                            conversational += 1;
                        }
                        "progress" | "tool_use" | "tool_result" => {}
                        _ => {}
                    }
                }
                Err(_) => {
                    unmatched.push(format!("line {line_no}: not valid JSON"));
                }
            }
        }
        if codex_envelopes > 0 {
            unmatched.push(format!(
                "{codex_envelopes} session_meta record(s) carry a `payload` envelope \
                 (Codex rollout shape, not Qoder)"
            ));
        }

        if json_lines == 0 {
            return Err(ProviderError::AmbiguousVariant(format!(
                "no JSON lines parsed in {0} sampled lines",
                sample.len()
            )));
        }

        matched.push(format!("{json_lines} sampled lines are valid JSON"));

        // Qoder format is distinct: session_meta header + user/assistant records
        // whose `type` is the role. Refuse if no Qoder-specific session_meta
        // marker is present — without it, type:user/assistant could be Claude,
        // causing ambiguous selection.
        if session_meta == 0 {
            return Err(ProviderError::AmbiguousVariant(
                "no Qoder session_meta records found in sampled lines".into(),
            ));
        }

        let confidence = if conversational > 0 && session_meta > 0 {
            matched.push(format!(
                "{session_meta} session_meta headers, {conversational} conversational messages"
            ));
            Confidence::Confirmed
        } else if conversational > 0 {
            matched.push(format!("{conversational} user/assistant records found"));
            Confidence::High
        } else {
            matched.push(format!("{session_meta} session_meta headers found"));
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

            let rec: QoderRecord = match serde_json::from_str(parse_line) {
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

            match rec.r#type.as_str() {
                "session_meta" => {
                    // Identity may live at top level of the record or nested in
                    // the `session_meta` body object; probe both leniently.
                    let sid = rec
                        .session_id
                        .as_deref()
                        .filter(|s| !s.trim().is_empty())
                        .or_else(|| {
                            rec.session_meta
                                .as_ref()
                                .and_then(|m| m.get("session_id"))
                                .and_then(serde_json::Value::as_str)
                        })
                        .map(str::trim)
                        .filter(|s| !s.is_empty());
                    if let Some(id) = sid {
                        if report.session_native_id.is_none() {
                            report.session_native_id = Some(id.to_string());
                            report.session_observation.provider_session_id =
                                MetadataResolution::Resolved(id.to_string());
                        }
                        if !session_ids.iter().any(|s| s == id) {
                            session_ids.push(id.to_string());
                        }
                    }
                    // cwd observed from the same session_meta record (pair preserved).
                    if !report.session_observation.pair_observed {
                        let cwd = rec
                            .cwd
                            .as_deref()
                            .filter(|s| !s.trim().is_empty())
                            .or_else(|| {
                                rec.session_meta
                                    .as_ref()
                                    .and_then(|m| m.get("cwd"))
                                    .and_then(serde_json::Value::as_str)
                            })
                            .map(str::trim)
                            .filter(|s| !s.is_empty());
                        if let Some(cwd) = cwd {
                            report.session_observation.original_working_directory =
                                MetadataResolution::Resolved(cwd.to_string());
                            report.session_observation.pair_observed = true;
                        }
                    }
                }
                "user" | "assistant" => {
                    let role = rec.r#type.as_str();
                    let Some(msg) = &rec.message else {
                        report.skipped += 1;
                        report.diagnostics.push(format!(
                            "line {}: {role} record without `message` body, skipped",
                            line_no + 1
                        ));
                        continue;
                    };
                    let content = msg.content.as_ref().unwrap_or(&serde_json::Value::Null);
                    let text = qoder_content_text(content);
                    if text.trim().is_empty() {
                        continue;
                    }
                    let timestamp = msg
                        .timestamp
                        .as_deref()
                        .filter(|s| !s.trim().is_empty())
                        .or(rec.timestamp.as_deref().filter(|s| !s.trim().is_empty()));
                    sink.emit_message(MessageEvent {
                        session: None,
                        seq,
                        native_id: "",
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
                _ => {
                    // progress, tool_use, tool_result, and unknown types are
                    // non-conversational → skipped.
                }
            }
        }

        // Multi-session diagnostic.
        if session_ids.len() > 1 {
            report.session_observation.multi_session = true;
            report.session_observation.provider_session_id = MetadataResolution::Ambiguous;
            report.diagnostics.push(format!(
                "文件包含 {} 个不同 id——单文件=单会话，全部消息归属首个会话 {}",
                session_ids.len(),
                session_ids[0]
            ));
        }

        Ok(report)
    }
}

/// Extract plain text from a Qoder content value.
///
/// Qoder content can be a string or an array of `{type:"text", text:"..."}`
/// blocks (similar to Claude's content blocks).
fn qoder_content_text(content: &serde_json::Value) -> String {
    match content {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Array(blocks) => {
            let mut buf = String::new();
            for block in blocks {
                if block.get("type").and_then(serde_json::Value::as_str) == Some("text")
                    && let Some(t) = block.get("text").and_then(serde_json::Value::as_str)
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
        let adapter = QoderAdapter::new();
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
        let adapter = QoderAdapter::new();
        assert!(adapter.probe(b"").is_err());
    }

    #[test]
    fn probe_confirms_qoder_transcript_jsonl() {
        let adapter = QoderAdapter::new();
        let fixture = r#"{"type":"session_meta","session_id":"sess-1","cwd":"/work","timestamp":"2026-01-01T00:00:00Z"}
{"type":"user","message":{"role":"user","content":"hello"}}
{"type":"assistant","message":{"role":"assistant","content":"hi there"}}
"#;
        let result = adapter.probe(fixture.as_bytes()).unwrap();
        assert_eq!(result.variant_id, VARIANT_ID);
        assert_eq!(result.confidence, Confidence::Confirmed);
    }

    #[test]
    fn probe_rejects_non_qoder_jsonl() {
        let adapter = QoderAdapter::new();
        let fixture = "{\"foo\":1}\n{\"bar\":2}\n";
        assert!(adapter.probe(fixture.as_bytes()).is_err());
    }

    #[test]
    fn probe_rejects_codex_rollout_envelopes() {
        // `session_meta` 这个 type 名不是 Qoder 独有：Codex rollout 的每条记录都是
        // `{timestamp, type, payload}` 封套，首行同样是顶层 `type:"session_meta"`。
        // 若不看 `payload` 判别位，Qoder 会对 Codex rollout 报 High；codex 自身在
        // 容忍范围内的坏行下会从 Confirmed 降到 High，两者并列即触发
        // `select_and_stage_source` 的 tie 分支拒绝整个源——codex 的真实 golden
        // fixture 恰好含一条故意截断的记录，因此这不是理论风险。
        let adapter = QoderAdapter::new();
        let rollout = concat!(
            r#"{"timestamp":"2026-07-26T08:00:00.000Z","type":"session_meta","payload":{"session_id":"s-1","cwd":"/work"}}"#,
            "\n",
            r#"{"timestamp":"2026-07-26T08:00:01.000Z","type":"response_item","payload":{"type":"message","id":"m-1","role":"user","content":[{"type":"input_text","text":"hi"}]}}"#,
            "\n",
        );
        assert!(
            adapter.probe(rollout.as_bytes()).is_err(),
            "带 payload 封套的 session_meta 是 Codex rollout，Qoder 必须拒绝认领"
        );
    }

    #[test]
    fn probe_rejects_chat_only_without_session_meta() {
        let adapter = QoderAdapter::new();
        let fixture = r#"{"type":"user","message":{"role":"user","content":"hi"}}
{"type":"assistant","message":{"role":"assistant","content":"hello"}}
"#;
        // Without session_meta, this could be Claude — must refuse to avoid
        // ambiguous selection.
        assert!(adapter.probe(fixture.as_bytes()).is_err());
    }

    #[test]
    fn parse_extracts_session_and_messages() {
        let adapter = QoderAdapter::new();
        let fixture = r#"{"type":"session_meta","session_id":"sess-1","cwd":"/home/user/proj","timestamp":"2026-01-01T00:00:00Z"}
{"type":"user","message":{"role":"user","content":"hello world"}}
{"type":"assistant","message":{"role":"assistant","content":"hi there"}}
"#;
        let mut sink = CountSink { count: 0 };
        let report = adapter.parse(fixture.as_bytes(), &mut sink).unwrap();
        assert_eq!(sink.count, 2);
        assert_eq!(report.committed, 2);
        assert_eq!(report.session_native_id.as_deref(), Some("sess-1"));
        assert!(report.session_observation.pair_observed);
    }

    #[test]
    fn parse_handles_array_content_blocks() {
        let adapter = QoderAdapter::new();
        let fixture = r#"{"type":"session_meta","session_id":"s1","cwd":"/p"}
{"type":"assistant","message":{"role":"assistant","content":[{"type":"text","text":"part1"},{"type":"text","text":"part2"}]}}
"#;
        let mut sink = CountSink { count: 0 };
        let report = adapter.parse(fixture.as_bytes(), &mut sink).unwrap();
        assert_eq!(report.committed, 1);
    }

    #[test]
    fn parse_skips_non_conversational_types() {
        let adapter = QoderAdapter::new();
        let fixture = r#"{"type":"session_meta","session_id":"s1","cwd":"/p"}
{"type":"progress","message":{"content":"thinking"}}
{"type":"tool_use","message":{"content":"bash"}}
{"type":"tool_result","message":{"content":"output"}}
{"type":"user","message":{"role":"user","content":"real msg"}}
"#;
        let mut sink = CountSink { count: 0 };
        let report = adapter.parse(fixture.as_bytes(), &mut sink).unwrap();
        assert_eq!(report.committed, 1);
    }

    #[test]
    fn parse_skips_invalid_json_lines() {
        let adapter = QoderAdapter::new();
        let fixture =
            "not json\n{\"type\":\"user\",\"message\":{\"role\":\"user\",\"content\":\"ok\"}}\n";
        let mut sink = CountSink { count: 0 };
        let report = adapter.parse(fixture.as_bytes(), &mut sink).unwrap();
        assert_eq!(report.committed, 1);
        assert_eq!(report.skipped, 1);
    }

    #[test]
    fn parse_multi_session_emits_diagnostic() {
        let adapter = QoderAdapter::new();
        let fixture = r#"{"type":"session_meta","session_id":"s1","cwd":"/p"}
{"type":"session_meta","session_id":"s2","cwd":"/q"}
{"type":"user","message":{"role":"user","content":"msg"}}
"#;
        let mut sink = CountSink { count: 0 };
        let report = adapter.parse(fixture.as_bytes(), &mut sink).unwrap();
        assert_eq!(report.committed, 1);
        assert!(!report.diagnostics.is_empty());
        assert!(report.session_observation.multi_session);
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
    fn parse_passes_noise_shaped_user_text_through_verbatim() {
        // 钉住测试：Qoder transcript JSONL 没有 system-reminder / AGENTS.md /
        // 环境上下文等注入概念（type 即角色，user 行就是用户原文）。形似噪声
        // 的文本必须逐字透传，防止将来把别家格式的过滤规则盲目搬来造成
        // silent drift。
        let adapter = QoderAdapter::new();
        let fixture = r##"{"type":"session_meta","session_id":"s1","cwd":"/p"}
{"type":"user","message":{"role":"user","content":"<system-reminder>reminder text</system-reminder>"}}
{"type":"user","message":{"role":"user","content":"# AGENTS.md instructions"}}
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

    #[test]
    fn parse_extracts_identity_from_nested_session_meta() {
        let adapter = QoderAdapter::new();
        let fixture = r#"{"type":"session_meta","session_meta":{"session_id":"nested-1","cwd":"/nested"}}
{"type":"user","message":{"role":"user","content":"msg"}}
"#;
        let mut sink = CountSink { count: 0 };
        let report = adapter.parse(fixture.as_bytes(), &mut sink).unwrap();
        assert_eq!(report.session_native_id.as_deref(), Some("nested-1"));
        assert_eq!(
            report.session_observation.original_working_directory,
            MetadataResolution::Resolved("/nested".to_string())
        );
    }
}
