//! Pi coding agent provider adapter.
//!
//! Parses Pi's session JSONL format: each line carries a `type` discriminator.
//! `type: "session"` is the header (carries `id`, `cwd`, `timestamp`, and — from
//! format version 2 onward — `version`); `type: "message"` wraps `message.role`
//! (user/assistant) and `message.content`. `type: "session_info"` carries
//! `name`; `custom_message`/`compaction`/`model_change` are non-conversational
//! and skipped by the canonical adapter.
//!
//! Format evidence: fast-resume (MIT) `src/adapters/pi.rs`. The type-based
//! dispatch and content extraction are adapted from fast-resume under MIT.
//!
//! # Session-tree lineage (format version 2/3)
//!
//! From version 2 onward every non-header record carries its own `id` and an
//! explicit `parentId`, so a Pi file is a **parent-linked tree**: two records
//! may share one `parentId` (a retried/abandoned branch), and the physical last
//! line is not necessarily on the same path as the first. Version 1 files carry
//! neither field and are plain linear appends. The discriminator is the header's
//! `version` key: absent means v1.
//!
//! This adapter indexes **every** conversational record in file order —
//! abandoned branches included, because their text is exactly what a history
//! search must be able to find — and it deliberately does **not** emit
//! `parent_native_id` edges. Emitting an edge requires promoting the record `id`
//! to a canonical native message identity, and that identity is adopted
//! verbatim and un-namespaced (`StableId::native(IdKind::Message, ..)`), unlike
//! session ids which are provider+installation scoped. Real Pi record ids are
//! 8 hex characters (32 bit) that are only unique *within one file*, while the
//! session id in the same header is a UUID — so promoting them would make two
//! records from two different sessions collide onto one message entity. Rather
//! than degrade silently, the parse report carries an explicit diagnostic
//! ([`PI_BRANCH_LINEAGE_DIAGNOSTIC_PREFIX`]) naming the declared version and the
//! number of lineage-bearing records, and the probe reports the same as matched
//! evidence. Modelling the tree needs document-scoped native message identity in
//! the composition root first; that is a shared-contract change, not a
//! per-adapter one.

use agent_session_grep_ports::MetadataResolution;
use agent_session_grep_ports::{
    AdapterManifest, CanonicalEventSink, Confidence, MessageEvent, ParseReport, ProbeResult,
    ProviderAdapter, ProviderError, manifest_for,
};

/// Variant id surfaced in probe results.
const VARIANT_ID: &str = "pi/session-jsonl-v1";

/// Number of non-blank lines to sample during probe (bounded, RFC-0002 §7).
const SAMPLE_LINE_LIMIT: usize = 8;

/// Lowest Pi format version that carries per-record `id` + `parentId` lineage.
const LINEAGE_MIN_VERSION: u64 = 2;

/// Prefix of the diagnostic emitted when a source carries session-tree lineage
/// this adapter deliberately does not model.
///
/// Public because the golden and property suites are separate crates: they must
/// recognise the diagnostic without re-hardcoding its text, which is exactly how
/// a pinned marker drifts away from the code that produces it.
pub const PI_BRANCH_LINEAGE_DIAGNOSTIC_PREFIX: &str = "会话树血缘未建模";

/// Pi coding agent adapter: parses session JSONL with `type`-discriminated records.
pub struct PiAdapter;

impl PiAdapter {
    pub fn new() -> Self {
        Self
    }
}

impl Default for PiAdapter {
    fn default() -> Self {
        Self::new()
    }
}

/// Minimal deserialization target for a Pi JSONL record.
///
/// Only fields needed for probe/parse are modeled; unknown fields are silently
/// ignored (forward-compatible).
#[derive(serde::Deserialize)]
struct PiRecord {
    #[serde(default)]
    r#type: String,
    #[serde(default)]
    id: Option<String>,
    /// Pi format version, only present on the `session` header from v2 onward.
    #[serde(default)]
    version: Option<u64>,
    /// Parent record id (session-tree edge); absent or `null` on a root record.
    #[serde(rename = "parentId", default)]
    parent_id: Option<String>,
    #[serde(default)]
    cwd: Option<String>,
    #[serde(default)]
    timestamp: Option<String>,
    #[serde(default)]
    message: Option<PiMessage>,
}

#[derive(serde::Deserialize)]
struct PiMessage {
    #[serde(default)]
    role: String,
    #[serde(default)]
    content: Option<serde_json::Value>,
    #[serde(default)]
    timestamp: Option<serde_json::Value>,
}

impl ProviderAdapter for PiAdapter {
    fn provider_id(&self) -> &str {
        "pi"
    }

    fn manifest(&self) -> AdapterManifest {
        manifest_for(
            self.provider_id(),
            Some(1),
            &[
                "non-conversational types (session_info/compaction/custom_message) are skipped",
                "native message ids are not preserved (ids are derived, not native)",
                "format v2/v3 session-tree lineage (`parentId`) is reported as a \
                 diagnostic, not modeled: every branch is indexed linearly, no parent edges",
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
        let mut session_headers = 0usize;
        let mut message_records = 0usize;
        let mut conversational = 0usize;
        let mut declared_version: Option<u64> = None;
        let mut lineage_records = 0usize;

        for &(line_no, line) in &sample {
            match serde_json::from_str::<serde_json::Value>(line) {
                Ok(v) => {
                    json_lines += 1;
                    let t = v
                        .get("type")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("");
                    if t == "session" {
                        session_headers += 1;
                        if declared_version.is_none() {
                            declared_version = v.get("version").and_then(serde_json::Value::as_u64);
                        }
                    }
                    if v.get("parentId")
                        .and_then(serde_json::Value::as_str)
                        .is_some_and(|parent| !parent.trim().is_empty())
                    {
                        lineage_records += 1;
                    }
                    if t == "message" {
                        message_records += 1;
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

        // Pi format is distinct: type=session header + type=message records with
        // nested message.role. Refuse if no Pi-specific type markers present —
        // Low would compete with Claude/Codex adapters and cause ambiguous selection.
        if session_headers == 0 && message_records == 0 {
            return Err(ProviderError::AmbiguousVariant(
                "no Pi session/message type records found in sampled lines".into(),
            ));
        }

        let confidence = if conversational > 0 && session_headers > 0 {
            matched.push(format!(
                "{session_headers} session headers, {conversational} conversational messages"
            ));
            Confidence::Confirmed
        } else if conversational > 0 || message_records > 0 {
            matched.push(format!("{message_records} message records found"));
            Confidence::High
        } else {
            matched.push(format!("{session_headers} session headers found"));
            Confidence::High
        };

        // Lineage is reported as evidence, never as a discriminator: openclaw
        // transcripts are the same v3 session JSONL (go-no-go §6 row 13), so the
        // tie is resolved by the canonical root, not by content. Confidence and
        // variant stay exactly as computed above.
        if let Some(version) = declared_version {
            matched.push(format!("session header declares format version {version}"));
        }
        if lineage_records > 0 {
            matched.push(format!(
                "{lineage_records} sampled records carry parentId lineage (session tree, not modeled)"
            ));
        }

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
        // 会话树血缘的事实计量（不建模，只如实上报）：首个声明的格式版本 +
        // 携带非空 parentId 的记录数。两者都是 O(1) 状态，不破坏"内存上界是
        // 单条记录"的流式契约（RFC-0002 §7）。
        let mut declared_version: Option<u64> = None;
        let mut lineage_records = 0usize;

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

            let rec: PiRecord = match serde_json::from_str(parse_line) {
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

            // 血缘计量先于类型分发：非对话记录（model_change/session_info/
            // compaction）同样带 parentId，是会话树的一部分，漏计会低报事实。
            if rec
                .parent_id
                .as_deref()
                .is_some_and(|parent| !parent.trim().is_empty())
            {
                lineage_records += 1;
            }

            match rec.r#type.as_str() {
                "session" => {
                    // 首个显式声明的 version 生效：v1 无该键，故 None 不覆盖。
                    if declared_version.is_none() && rec.version.is_some() {
                        declared_version = rec.version;
                    }
                    if let Some(id) = rec.id.as_deref()
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
                        // cwd observed from the same session record (pair preserved).
                        if !report.session_observation.pair_observed
                            && let Some(cwd) = rec.cwd.as_deref()
                            && !cwd.trim().is_empty()
                        {
                            report.session_observation.original_working_directory =
                                MetadataResolution::Resolved(cwd.trim().to_string());
                            report.session_observation.pair_observed = true;
                        }
                    }
                }
                "message" => {
                    let Some(msg) = &rec.message else {
                        report.skipped += 1;
                        report.diagnostics.push(format!(
                            "line {}: message record without `message` body, skipped",
                            line_no + 1
                        ));
                        continue;
                    };
                    let role = msg.role.as_str();
                    if !matches!(role, "user" | "assistant") {
                        continue;
                    }
                    let content = msg.content.as_ref().unwrap_or(&serde_json::Value::Null);
                    let text = pi_content_text(content);
                    if text.trim().is_empty() {
                        continue;
                    }
                    let timestamp = msg
                        .timestamp
                        .as_ref()
                        .and_then(|v| v.as_str())
                        .or(rec.timestamp.as_deref());
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
                    // session_info, custom_message, compaction, branch_summary,
                    // model_change, thinking_level_change, and unknown types are
                    // non-conversational → skipped (they may still carry
                    // `id`/`parentId`, already counted as lineage above).
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

        // 会话树血缘诊断：把"这是 v2/v3、分支结构未建模"变成可见事实，而不是
        // 静默按线性解析。触发条件是两个独立的格式事实之一——头部声明的
        // version >= 2，或任意记录携带非空 parentId——因为真实语料里两者都可能
        // 单独出现（头部缺失的截断文件仍有 parentId；只有一条根记录的 v3 会话
        // 一条 parentId 也没有）。
        if lineage_records > 0 || declared_version.is_some_and(|v| v >= LINEAGE_MIN_VERSION) {
            let version = match declared_version {
                Some(version) => version.to_string(),
                None => "未声明（头部缺失或为 v1）".to_string(),
            };
            report.diagnostics.push(format!(
                "{PI_BRANCH_LINEAGE_DIAGNOSTIC_PREFIX}：格式 version={version}，\
                 {lineage_records} 条记录带 parentId。全部消息按文件顺序逐条索引\
                 （含被放弃分支，不丢正文），但不发出 parent 边——Pi 逐条 entry id \
                 是仅文件内唯一的 32 位标记，提升为全局 native 消息身份会跨会话碰撞。"
            ));
        }

        Ok(report)
    }
}

/// Extract plain text from a Pi content value.
///
/// Pi content can be a string or an array of content blocks. Two block kinds
/// carry prose and both are extracted, in block order:
///
/// - `{"type":"text","text":…}` (also seen with an extra `textSignature`);
/// - `{"type":"thinking","thinking":…,"thinkingSignature":…}` — the reasoning
///   prose lives on the `thinking` key, **not** on `text`. Reading only `text`
///   made a thinking-only assistant record project to an empty body, which this
///   adapter then dropped without a diagnostic: the record vanished from the
///   index entirely. Shape evidence: sessiongrep `src/providers/pi.rs` fixture
///   (`{"type":"thinking","thinking":…}` inside pi assistant content),
///   cc-sessions-viewer `src-tauri/src/agents/pi.rs` (`"thinking"` arm reading
///   `.get("thinking")`), Recall `src/adapters/pi.rs` fixture, and the local
///   authorized `~/.pi/agent/sessions` corpus.
///
/// Blank/whitespace-only prose contributes nothing (no empty fragments), the
/// same way cc-sessions-viewer drops empty thinking blocks. `text` block
/// handling is unchanged. `toolCall` blocks are deliberately left out — see the
/// module docs and the `tool_activity` capability row.
fn pi_content_text(content: &serde_json::Value) -> String {
    match content {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Array(blocks) => {
            let mut buf = String::new();
            for block in blocks {
                let piece = match block.get("type").and_then(serde_json::Value::as_str) {
                    Some("text") => block.get("text").and_then(serde_json::Value::as_str),
                    Some("thinking") => block
                        .get("thinking")
                        .and_then(serde_json::Value::as_str)
                        .filter(|t| !t.trim().is_empty()),
                    _ => None,
                };
                if let Some(t) = piece {
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
        let adapter = PiAdapter::new();
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
        let adapter = PiAdapter::new();
        assert!(adapter.probe(b"").is_err());
    }

    #[test]
    fn probe_confirms_pi_session_jsonl() {
        let adapter = PiAdapter::new();
        let fixture = r#"{"type":"session","id":"sess-1","cwd":"/work","timestamp":"2026-01-01T00:00:00Z"}
{"type":"message","message":{"role":"user","content":"hello"}}
{"type":"message","message":{"role":"assistant","content":"hi there"}}
"#;
        let result = adapter.probe(fixture.as_bytes()).unwrap();
        assert_eq!(result.variant_id, VARIANT_ID);
        assert_eq!(result.confidence, Confidence::Confirmed);
    }

    #[test]
    fn probe_rejects_non_pi_jsonl() {
        let adapter = PiAdapter::new();
        let fixture = "{\"foo\":1}\n{\"bar\":2}\n";
        assert!(adapter.probe(fixture.as_bytes()).is_err());
    }

    #[test]
    fn parse_extracts_session_and_messages() {
        let adapter = PiAdapter::new();
        let fixture = r#"{"type":"session","id":"sess-1","cwd":"/home/user/proj","timestamp":"2026-01-01T00:00:00Z"}
{"type":"message","message":{"role":"user","content":"hello world"}}
{"type":"message","message":{"role":"assistant","content":"hi there"}}
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
        let adapter = PiAdapter::new();
        let fixture = r#"{"type":"session","id":"s1","cwd":"/p"}
{"type":"message","message":{"role":"assistant","content":[{"type":"text","text":"part1"},{"type":"text","text":"part2"}]}}
"#;
        let mut sink = CountSink { count: 0 };
        let report = adapter.parse(fixture.as_bytes(), &mut sink).unwrap();
        assert_eq!(report.committed, 1);
    }

    #[test]
    fn content_text_extracts_thinking_block_prose() {
        // Pi 的 thinking block 正文在 `thinking` 键上（另带 `thinkingSignature`），
        // 不在 `text` 上。只读 `text` 时，thinking-only 的 assistant 记录整条
        // 投影为空正文，随后被 `text.trim().is_empty()` 分支**无声丢弃**（连
        // skipped 都不计）——记录彻底不进索引。
        assert_eq!(
            pi_content_text(&serde_json::json!([
                {"type": "thinking", "thinking": "synthetic reasoning", "thinkingSignature": "sig"}
            ])),
            "synthetic reasoning"
        );
    }

    #[test]
    fn content_text_keeps_thinking_and_text_in_block_order() {
        // 真实语料里 thinking 在数组首位、text 在后（各带自己的 signature 字段）。
        assert_eq!(
            pi_content_text(&serde_json::json!([
                {"type": "thinking", "thinking": "first I reason", "thinkingSignature": "sig-a"},
                {"type": "text", "text": "then I answer", "textSignature": "sig-b"}
            ])),
            "first I reason\nthen I answer"
        );
    }

    #[test]
    fn content_text_ignores_blank_thinking_and_tool_call_blocks() {
        // 空白 thinking 不产出空片段；`toolCall` 块仍不进正文（与
        // capability.rs 的 tool_activity=Unsupported 口径一致，见模块文档）。
        assert_eq!(
            pi_content_text(&serde_json::json!([
                {"type": "thinking", "thinking": "   "},
                {"type": "toolCall", "id": "t1", "name": "ls", "arguments": {"path": "/tmp"}},
                {"type": "text", "text": "only real text survives"}
            ])),
            "only real text survives"
        );
    }

    #[test]
    fn content_text_never_reads_thinking_from_a_non_thinking_block() {
        // 只有 `type:"thinking"` 的块才允许把 `thinking` 键当正文。
        assert_eq!(
            pi_content_text(&serde_json::json!([
                {"type": "toolCall", "name": "ls", "thinking": "not a body"},
                {"type": "text", "text": "body"}
            ])),
            "body"
        );
    }

    #[test]
    fn parse_commits_thinking_only_assistant_record() {
        // 端到端：thinking-only 记录必须被提交，而不是无声消失。
        let adapter = PiAdapter::new();
        let fixture = concat!(
            r#"{"type":"session","id":"s1","cwd":"/p","version":3}"#,
            "\n",
            r#"{"type":"message","id":"a1","parentId":"u1","message":{"role":"assistant","content":[{"type":"thinking","thinking":"synthetic reasoning","thinkingSignature":"sig"}]}}"#,
            "\n",
        );
        let mut sink = CountSink { count: 0 };
        let report = adapter.parse(fixture.as_bytes(), &mut sink).unwrap();
        assert_eq!(report.committed, 1, "thinking-only 记录必须进索引");
        assert_eq!(sink.count, 1);
    }

    #[test]
    fn parse_skips_non_conversational_types() {
        let adapter = PiAdapter::new();
        let fixture = r#"{"type":"session","id":"s1","cwd":"/p"}
{"type":"session_info","name":"my session"}
{"type":"compaction","summary":"compacted data"}
{"type":"message","message":{"role":"user","content":"real msg"}}
"#;
        let mut sink = CountSink { count: 0 };
        let report = adapter.parse(fixture.as_bytes(), &mut sink).unwrap();
        assert_eq!(report.committed, 1);
    }

    #[test]
    fn parse_skips_invalid_json_lines() {
        let adapter = PiAdapter::new();
        let fixture =
            "not json\n{\"type\":\"message\",\"message\":{\"role\":\"user\",\"content\":\"ok\"}}\n";
        let mut sink = CountSink { count: 0 };
        let report = adapter.parse(fixture.as_bytes(), &mut sink).unwrap();
        assert_eq!(report.committed, 1);
        assert_eq!(report.skipped, 1);
    }

    #[test]
    fn parse_multi_session_emits_diagnostic() {
        let adapter = PiAdapter::new();
        let fixture = r#"{"type":"session","id":"s1","cwd":"/p"}
{"type":"session","id":"s2","cwd":"/q"}
{"type":"message","message":{"role":"user","content":"msg"}}
"#;
        let mut sink = CountSink { count: 0 };
        let report = adapter.parse(fixture.as_bytes(), &mut sink).unwrap();
        assert_eq!(report.committed, 1);
        assert!(!report.diagnostics.is_empty());
        assert!(report.session_observation.multi_session);
    }

    /// 该 fixture 里有多少条血缘诊断。
    fn lineage_diagnostics(report: &ParseReport) -> usize {
        report
            .diagnostics
            .iter()
            .filter(|d| d.starts_with(PI_BRANCH_LINEAGE_DIAGNOSTIC_PREFIX))
            .count()
    }

    #[test]
    fn parse_v1_corpus_reports_no_branch_lineage() {
        // 钉住负向：v1 无 version 键、无 entry id/parentId → 不得凭空产生血缘诊断
        // （否则诊断会退化成噪音，读者无法据此判断哪些源真是会话树）。
        let adapter = PiAdapter::new();
        let fixture = r#"{"type":"session","id":"s1","cwd":"/p"}
{"type":"message","message":{"role":"user","content":"linear one"}}
{"type":"message","message":{"role":"assistant","content":"linear two"}}
"#;
        let mut sink = CountSink { count: 0 };
        let report = adapter.parse(fixture.as_bytes(), &mut sink).unwrap();
        assert_eq!(report.committed, 2);
        assert_eq!(lineage_diagnostics(&report), 0);
        assert!(report.diagnostics.is_empty());
    }

    #[test]
    fn parse_v3_branch_reports_lineage_once_and_keeps_every_branch() {
        // 正向：v3 头部 + 两条同 parentId 的分支记录。全部消息（含被放弃分支）
        // 必须都进索引，且恰好一条血缘诊断——分支结构不再静默丢失。
        let adapter = PiAdapter::new();
        let fixture = r#"{"type":"session","version":3,"id":"s3","cwd":"/p"}
{"type":"message","id":"aa000001","parentId":null,"message":{"role":"user","content":"root"}}
{"type":"message","id":"aa000002","parentId":"aa000001","message":{"role":"assistant","content":"kept branch"}}
{"type":"message","id":"aa000003","parentId":"aa000001","message":{"role":"assistant","content":"abandoned branch"}}
"#;
        let mut sink = TextSink { texts: vec![] };
        let report = adapter.parse(fixture.as_bytes(), &mut sink).unwrap();
        assert_eq!(report.committed, 3, "两条分支都必须索引，不得只留一条");
        assert_eq!(
            sink.texts,
            vec![
                "root".to_string(),
                "kept branch".to_string(),
                "abandoned branch".to_string(),
            ]
        );
        assert_eq!(lineage_diagnostics(&report), 1);
        let diagnostic = report
            .diagnostics
            .iter()
            .find(|d| d.starts_with(PI_BRANCH_LINEAGE_DIAGNOSTIC_PREFIX))
            .expect("血缘诊断必须存在");
        assert!(
            diagnostic.contains("version=3") && diagnostic.contains("2 条记录带 parentId"),
            "诊断必须报出声明版本与血缘记录数，实际：{diagnostic}"
        );
    }

    #[test]
    fn parse_reports_lineage_from_parent_id_even_without_a_version_header() {
        // 截断/无头文件仍可能带 parentId：两个格式事实各自独立触发诊断，
        // 否则丢头的 v3 源会退回"静默线性"。
        let adapter = PiAdapter::new();
        let fixture = r#"{"type":"message","id":"aa000001","message":{"role":"user","content":"a"}}
{"type":"message","id":"aa000002","parentId":"aa000001","message":{"role":"assistant","content":"b"}}
"#;
        let mut sink = CountSink { count: 0 };
        let report = adapter.parse(fixture.as_bytes(), &mut sink).unwrap();
        assert_eq!(report.committed, 2);
        assert_eq!(lineage_diagnostics(&report), 1);
        assert!(
            report.diagnostics[0].contains("未声明"),
            "无 version 头时必须如实说明版本未声明，实际：{}",
            report.diagnostics[0]
        );
    }

    #[test]
    fn parse_counts_lineage_on_non_conversational_records() {
        // model_change / session_info 也是会话树节点：漏计会低报"这是一棵树"。
        let adapter = PiAdapter::new();
        let fixture = r#"{"type":"session","version":3,"id":"s3","cwd":"/p"}
{"type":"model_change","id":"aa000001","parentId":null,"provider":"synthetic","modelId":"m"}
{"type":"session_info","id":"aa000002","parentId":"aa000001","name":"named"}
{"type":"message","id":"aa000003","parentId":"aa000002","message":{"role":"user","content":"only msg"}}
"#;
        let mut sink = CountSink { count: 0 };
        let report = adapter.parse(fixture.as_bytes(), &mut sink).unwrap();
        assert_eq!(report.committed, 1);
        assert_eq!(lineage_diagnostics(&report), 1);
        assert!(
            report.diagnostics[0].contains("2 条记录带 parentId"),
            "非对话记录的 parentId 必须计入，实际：{}",
            report.diagnostics[0]
        );
    }

    #[test]
    fn parse_v3_never_promotes_record_ids_to_native_identity() {
        // 钉住"不建模"的具体含义：即便记录带 id/parentId，事件仍以空 native_id
        // 与 None parent 上报。若将来改为发出边，本测试必须与 capability.rs 的
        // `context` 列、composition root 的消息身份策略一起评审后再改。
        let adapter = PiAdapter::new();
        let fixture = r#"{"type":"session","version":3,"id":"s3","cwd":"/p"}
{"type":"message","id":"aa000001","parentId":null,"message":{"role":"user","content":"root"}}
{"type":"message","id":"aa000002","parentId":"aa000001","message":{"role":"assistant","content":"child"}}
"#;
        let mut sink = IdentitySink { seen: vec![] };
        let report = adapter.parse(fixture.as_bytes(), &mut sink).unwrap();
        assert_eq!(report.committed, 2);
        assert_eq!(
            sink.seen,
            vec![(String::new(), None, false), (String::new(), None, false),]
        );
    }

    struct IdentitySink {
        /// (native_id, parent_native_id, is_sidechain)
        seen: Vec<(String, Option<String>, bool)>,
    }
    impl CanonicalEventSink for IdentitySink {
        fn emit_message(
            &mut self,
            event: MessageEvent<'_>,
        ) -> agent_session_grep_ports::PortResult<()> {
            self.seen.push((
                event.native_id.to_string(),
                event.parent_native_id.map(str::to_string),
                event.is_sidechain,
            ));
            Ok(())
        }
    }

    #[test]
    fn probe_reports_declared_version_and_lineage_as_evidence() {
        let adapter = PiAdapter::new();
        let fixture = r#"{"type":"session","version":3,"id":"s3","cwd":"/p","timestamp":"2026-01-01T00:00:00Z"}
{"type":"message","id":"aa000001","parentId":null,"message":{"role":"user","content":"root"}}
{"type":"message","id":"aa000002","parentId":"aa000001","message":{"role":"assistant","content":"child"}}
"#;
        let result = adapter.probe(fixture.as_bytes()).unwrap();
        // variant 与 confidence 不因 v3 判别而改变：pi/openclaw 的内容歧义仍由
        // 规范根收口（go-no-go §6 row 13），probe 只多报事实。
        assert_eq!(result.variant_id, VARIANT_ID);
        assert_eq!(result.confidence, Confidence::Confirmed);
        assert!(
            result
                .matched_evidence
                .iter()
                .any(|e| e.contains("format version 3")),
            "probe 必须报出声明的格式版本，实际：{:?}",
            result.matched_evidence
        );
        assert!(
            result
                .matched_evidence
                .iter()
                .any(|e| e.contains("parentId lineage")),
            "probe 必须报出血缘记录，实际：{:?}",
            result.matched_evidence
        );
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
        // 钉住测试：Pi session JSONL 没有 system-reminder / AGENTS.md /
        // 环境上下文等注入概念（message.role 就是角色，user 行就是用户原文）。
        // 形似噪声的文本必须逐字透传，防止将来把别家格式的过滤规则盲目搬来
        // 造成 silent drift。
        let adapter = PiAdapter::new();
        let fixture = r##"{"type":"session","id":"s1","cwd":"/p"}
{"type":"message","message":{"role":"user","content":"<system-reminder>reminder text</system-reminder>"}}
{"type":"message","message":{"role":"user","content":"# AGENTS.md instructions"}}
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
