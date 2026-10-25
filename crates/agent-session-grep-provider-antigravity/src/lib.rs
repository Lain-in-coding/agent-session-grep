//! Antigravity transcript and conversation-snapshot adapter.
//!
//! JSONL preserves the original visible content (or its existing visible
//! `thinking` fallback), dense emitted ordinals and exact snapshot line spans.
//! Stored `step_index` is separate source evidence; it is never fabricated into
//! a provider-native message or session ID. The composition root chooses one
//! authoritative representation and supplies its source/session namespace.
//!
//! Conversation SQLite snapshots additionally support the observed CLI 1.1.16
//! protobuf Step subset. See [`protobuf`] for the pinned field evidence and
//! compatibility boundary. This crate never opens a source path or reads a WAL.

use agent_session_grep_ports::{
    AdapterManifest, CanonicalEventSink, Confidence, MessageEvent, ParseReport, ProbeResult,
    ProviderAdapter, ProviderError, ReadOnlySource, SliceSource, manifest_for,
};
use std::io::{BufRead, Read};
use std::time::Instant;

pub mod protobuf;

/// Existing JSONL variant; its golden fixture remains at revision 1.
pub const TRANSCRIPT_VARIANT_ID: &str = "antigravity/transcript-jsonl-v1";
/// Additive, structurally validated conversation snapshot variant.
pub const CONVERSATION_VARIANT_ID: &str = "antigravity/conversation-sqlite-step-v1";
const VARIANT_ID: &str = TRANSCRIPT_VARIANT_ID;
const SAMPLE_LINE_LIMIT: usize = 50;
const MAX_STEPS: usize = 250_000;
const MAX_DIAGNOSTICS: usize = 64;

/// One optional original deadline, passed unchanged through every parse stage.
/// Existing APIs keep their compatibility behavior with no implicit new clock.
#[derive(Clone, Copy)]
pub(crate) struct ParseDeadline(Option<Instant>);

impl ParseDeadline {
    pub(crate) fn unlimited() -> Self {
        Self(None)
    }
    fn at(end: Instant) -> Self {
        Self(Some(end))
    }
    pub(crate) fn expired(self) -> bool {
        self.0.is_some_and(|end| Instant::now() >= end)
    }
    pub(crate) fn check(self) -> Result<(), ProviderError> {
        if self.expired() {
            Err(Self::exceeded())
        } else {
            Ok(())
        }
    }
    pub(crate) fn exceeded() -> ProviderError {
        ProviderError::StructuralFatal("Antigravity deadline exceeded".into())
    }
    fn io_check(self) -> std::io::Result<()> {
        if self.expired() {
            Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "Antigravity deadline exceeded",
            ))
        } else {
            Ok(())
        }
    }
    fn port_check(self) -> agent_session_grep_ports::PortResult<()> {
        if self.expired() {
            Err(agent_session_grep_ports::PortError::SourceIo(
                "Antigravity deadline exceeded".into(),
            ))
        } else {
            Ok(())
        }
    }
    fn provider_error(self, error: ProviderError) -> ProviderError {
        if self.expired() {
            Self::exceeded()
        } else {
            redact_io(error)
        }
    }
    pub(crate) fn sql_error(self, _: rusqlite::Error) -> ProviderError {
        if self.expired() {
            Self::exceeded()
        } else {
            ProviderError::StructuralFatal(
                "Antigravity snapshot: SQLite operation failed; source details withheld".into(),
            )
        }
    }
}

/// Cap one I/O/byte-copy operation before rechecking the caller's deadline.
const DEADLINE_READ_CHUNK_BYTES: usize = 64 * 1024;

struct DeadlineSource<'a> {
    source: &'a dyn ReadOnlySource,
    deadline: ParseDeadline,
}
impl ReadOnlySource for DeadlineSource<'_> {
    fn len(&self) -> u64 {
        self.source.len()
    }
    fn open(&self) -> agent_session_grep_ports::PortResult<Box<dyn BufRead + Send + '_>> {
        self.deadline.port_check()?;
        let opened = self.source.open();
        self.deadline.port_check()?;
        let inner = opened.map_err(|_| {
            agent_session_grep_ports::PortError::SourceIo("Antigravity snapshot open failed".into())
        })?;
        Ok(Box::new(DeadlineReader {
            inner,
            deadline: self.deadline,
        }))
    }
}
struct DeadlineReader<R> {
    inner: R,
    deadline: ParseDeadline,
}
impl<R: Read> Read for DeadlineReader<R> {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        self.deadline.io_check()?;
        let length = bytes.len().min(DEADLINE_READ_CHUNK_BYTES);
        let read = self.inner.read(&mut bytes[..length]);
        self.deadline.io_check()?;
        read.map_err(|_| std::io::Error::other("Antigravity snapshot read failed"))
    }
}
impl<R: BufRead> BufRead for DeadlineReader<R> {
    fn fill_buf(&mut self) -> std::io::Result<&[u8]> {
        let deadline = self.deadline;
        deadline.io_check()?;
        let available = self.inner.fill_buf();
        deadline.io_check()?;
        let available =
            available.map_err(|_| std::io::Error::other("Antigravity snapshot read failed"))?;
        Ok(&available[..available.len().min(DEADLINE_READ_CHUNK_BYTES)])
    }
    fn consume(&mut self, length: usize) {
        self.inner.consume(length);
    }
}

/// The container actually parsed, independent of the provider capability row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AntigravitySourceFormat {
    TranscriptJsonl,
    ConversationSqlite,
    ProtobufStep,
}

/// Exact association between one emitted message and the stored step ordinal.
///
/// `seq` is dense and source-local. `step_index` is the provider's actual
/// trajectory ordinal, including intervening non-message steps. Neither is a
/// durable native ID. SQLite rows have no trustworthy contiguous database span.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StepEvidence {
    pub seq: u32,
    pub step_index: u64,
    pub span: Option<(u64, u64)>,
}

/// Parsing plus source-completeness evidence for managed publication.
///
/// Callers must require `complete` AND `report.skipped == 0` before publishing
/// a replacement source. The compatibility `ProviderAdapter` API still returns
/// its existing report: intentional metadata omission does not increase its
/// skipped count. Gaps and missing step/source identity additionally make this
/// typed observation incomplete, even when a visible prefix could be parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AntigravityObservation {
    pub report: ParseReport,
    pub format: AntigravitySourceFormat,
    pub steps: Vec<StepEvidence>,
    pub complete: bool,
}

impl AntigravityObservation {
    fn new(format: AntigravitySourceFormat) -> Self {
        Self {
            report: ParseReport::default(),
            format,
            steps: Vec::new(),
            complete: true,
        }
    }

    pub(crate) fn diagnostic(&mut self, message: String) {
        if self.report.diagnostics.len() < MAX_DIAGNOSTICS {
            self.report.diagnostics.push(message);
        }
    }

    pub(crate) fn incomplete(&mut self, message: String, skipped: bool) {
        self.complete = false;
        if skipped {
            self.report.skipped += 1;
        }
        self.diagnostic(message);
    }

    pub(crate) fn emit(
        &mut self,
        sink: &mut dyn CanonicalEventSink,
        step_index: u64,
        mut event: MessageEvent<'_>,
        deadline: ParseDeadline,
    ) -> Result<(), ProviderError> {
        deadline.check()?;
        let seq = u32::try_from(self.report.committed).map_err(|_| {
            ProviderError::StructuralFatal("message ordinal exceeds supported range".into())
        })?;
        self.steps
            .try_reserve(1)
            .map_err(|_| ProviderError::Io("bounded step-evidence allocation failed".into()))?;
        event.seq = seq;
        let span = event.span;
        deadline.check()?;
        let emitted = sink.emit_message(event);
        deadline.check()?;
        emitted.map_err(|_| {
            ProviderError::StructuralFatal("Antigravity event sink rejected a message".into())
        })?;

        self.steps.push(StepEvidence {
            seq,
            step_index,
            span,
        });
        self.report.committed += 1;
        Ok(())
    }
}

/// Parses bytes supplied by the read-only source layer; never discovers paths.
pub struct AntigravityAdapter;

impl AntigravityAdapter {
    pub fn new() -> Self {
        Self
    }

    /// Parse a source-layer snapshot. SQLite bytes must already be a verified
    /// logical backup including committed WAL pages; raw DB bytes alone cannot
    /// prove that history is complete or current.
    pub fn parse_with_steps(
        &self,
        bytes: &[u8],
        sink: &mut dyn CanonicalEventSink,
    ) -> Result<AntigravityObservation, ProviderError> {
        self.parse_source_with_steps(&SliceSource::new(bytes), sink)
    }

    /// Parse a repeatable, verified snapshot with completeness/step evidence.
    /// For SQLite, the source layer owns logical Backup acquisition and freshness
    /// verification; this adapter never reads a native DB or its WAL separately.
    pub fn parse_source_with_steps(
        &self,
        source: &dyn ReadOnlySource,
        sink: &mut dyn CanonicalEventSink,
    ) -> Result<AntigravityObservation, ProviderError> {
        self.parse_source_with_deadline(source, sink, ParseDeadline::unlimited())
    }

    /// One caller-supplied original deadline covers source reads, JSONL/Step
    /// decoding, native SQLite VM execution and each sink emission. A timeout
    /// returns a content-free error, never a complete observation. Staging must
    /// discard all captured events on any error, including a sink that returned
    /// after `end`. Synchronous source/sink calls are checked again on return;
    /// this API cannot forcibly cancel a blocking third-party implementation.
    pub fn parse_source_with_steps_deadline(
        &self,
        source: &dyn ReadOnlySource,
        sink: &mut dyn CanonicalEventSink,
        end: Instant,
    ) -> Result<AntigravityObservation, ProviderError> {
        self.parse_source_with_deadline(source, sink, ParseDeadline::at(end))
    }

    fn parse_source_with_deadline(
        &self,
        source: &dyn ReadOnlySource,
        sink: &mut dyn CanonicalEventSink,
        deadline: ParseDeadline,
    ) -> Result<AntigravityObservation, ProviderError> {
        deadline.check()?;
        let bounded_source = DeadlineSource { source, deadline };
        let sqlite =
            source_is_sqlite(&bounded_source).map_err(|error| deadline.provider_error(error))?;
        deadline.check()?;
        let result = if sqlite {
            let bytes = agent_session_grep_ports::read_bounded_source(
                &bounded_source,
                agent_session_grep_ports::SQLITE_MAX_SOURCE_BYTES,
            )
            .map_err(|error| deadline.provider_error(error))?;
            deadline.check()?;
            if bytes.len() as u64 != source.len() {
                return Err(ProviderError::SourceChangedDuringRead(
                    "Antigravity snapshot length changed or read was incomplete".into(),
                ));
            }
            protobuf::parse_conversation_snapshot(&bytes, sink, deadline)
        } else {
            parse_transcript(&bounded_source, sink, deadline)
        };
        deadline.check()?;
        result
    }

    /// Parse one already-extracted, complete protobuf Step record.
    ///
    /// The caller supplies the actual stored `steps.idx`; this does not claim
    /// that an arbitrary loose `.pb` file has a supported conversation envelope.
    /// The span is exactly this record's supplied snapshot bytes, not an offset
    /// into an unrelated SQLite database or encrypted native file.
    pub fn parse_protobuf_step(
        &self,
        bytes: &[u8],
        step_index: u64,
        sink: &mut dyn CanonicalEventSink,
    ) -> Result<AntigravityObservation, ProviderError> {
        protobuf::parse_step_snapshot(bytes, step_index, sink, ParseDeadline::unlimited())
    }

    /// Decode and emit one caller-extracted Step under the same original
    /// deadline contract as [`Self::parse_source_with_steps_deadline`].
    pub fn parse_protobuf_step_deadline(
        &self,
        bytes: &[u8],
        step_index: u64,
        sink: &mut dyn CanonicalEventSink,
        end: Instant,
    ) -> Result<AntigravityObservation, ProviderError> {
        protobuf::parse_step_snapshot(bytes, step_index, sink, ParseDeadline::at(end))
    }
}

/// Inspect a verified source-layer snapshot without retaining or returning text.
///
/// Uses the same full validation as [`AntigravityAdapter::parse_with_steps`],
/// including late corrupt records, truncation and unsupported Step variants.
/// `report.committed` counts parsed messages; inspection does not publish them.
/// `steps` retains their original source ordinals/spans for caller-side routing.
/// Require `complete && report.skipped == 0` before source publication.
///
/// SQLite bytes must already be a verified logical Backup including committed
/// WAL pages. This API has no source path and cannot validate a raw DB-only copy
/// or infer a loose protobuf conversation envelope from readable strings.
pub fn inspect_snapshot(bytes: &[u8]) -> Result<AntigravityObservation, ProviderError> {
    struct DiscardMessages;
    impl CanonicalEventSink for DiscardMessages {
        fn emit_message(
            &mut self,
            _: MessageEvent<'_>,
        ) -> agent_session_grep_ports::PortResult<()> {
            Ok(())
        }
    }
    AntigravityAdapter::new().parse_with_steps(bytes, &mut DiscardMessages)
}

impl Default for AntigravityAdapter {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(serde::Deserialize)]
struct StepRecord {
    #[serde(default)]
    step_index: Option<u64>,
    #[serde(default)]
    source: Option<String>,
    #[serde(default)]
    r#type: Option<String>,
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    truncated_fields: Option<Vec<String>>,
    #[serde(default)]
    created_at: Option<String>,
    #[serde(default)]
    content: Option<serde_json::Value>,
    #[serde(default)]
    thinking: Option<String>,
}

fn redact_io(error: ProviderError) -> ProviderError {
    match error {
        ProviderError::Io(_) => ProviderError::Io("Antigravity snapshot read failed".into()),
        other => other,
    }
}

fn source_is_sqlite(source: &dyn ReadOnlySource) -> Result<bool, ProviderError> {
    let mut prefix = Vec::with_capacity(16);
    source
        .open()
        .map_err(|_| ProviderError::Io("Antigravity snapshot open failed".into()))?
        .take(16)
        .read_to_end(&mut prefix)
        .map_err(|_| ProviderError::Io("Antigravity snapshot header read failed".into()))?;
    Ok(prefix == protobuf::SQLITE_MAGIC)
}

fn parse_transcript(
    source: &dyn ReadOnlySource,
    sink: &mut dyn CanonicalEventSink,
    deadline: ParseDeadline,
) -> Result<AntigravityObservation, ProviderError> {
    deadline.check()?;
    let mut lines = agent_session_grep_ports::BoundedLineReader::new(
        source,
        agent_session_grep_ports::STREAM_RECORD_MAX_BYTES,
    )
    .map_err(|_| {
        deadline.provider_error(ProviderError::Io(
            "Antigravity transcript open failed".into(),
        ))
    })?;
    deadline.check()?;
    let mut result = AntigravityObservation::new(AntigravitySourceFormat::TranscriptJsonl);
    let mut previous_step = None;
    let mut records = 0usize;
    loop {
        deadline.check()?;
        let next = lines
            .next_record()
            .map_err(|error| deadline.provider_error(error))?;
        deadline.check()?;
        let Some(line) = next else {
            break;
        };
        let parse_line = std::str::from_utf8(line.bytes).map_err(|_| {
            ProviderError::AmbiguousVariant(
                "unknown Antigravity snapshot encoding; no plaintext transcript established".into(),
            )
        })?;
        if parse_line.trim().is_empty() {
            continue;
        }
        records += 1;
        if records > MAX_STEPS {
            return Err(ProviderError::StructuralFatal(
                "Antigravity transcript exceeds the supported step count".into(),
            ));
        }
        deadline.check()?;
        // Reader-based serde decoding rechecks every 4 KiB even inside a large
        // string/unknown JSON value, while preserving the existing field rules.
        let decoded = serde_json::from_reader(std::io::BufReader::with_capacity(
            4096,
            DeadlineReader {
                inner: std::io::Cursor::new(parse_line.as_bytes()),
                deadline,
            },
        ));
        deadline.check()?;
        let rec: StepRecord = match decoded {
            Ok(record) => record,
            Err(_) => {
                result.incomplete(
                    format!("line {}: invalid step JSON, skipped", line.number),
                    true,
                );
                continue;
            }
        };
        let Some(step_index) = rec.step_index else {
            result.incomplete(
                format!("line {}: step identity missing, skipped", line.number),
                true,
            );
            continue;
        };
        if previous_step.is_some_and(|previous| step_index <= previous) {
            result.incomplete(
                format!(
                    "line {}: repeated or out-of-order step identity, skipped",
                    line.number
                ),
                true,
            );
            continue;
        }
        if previous_step.map_or(step_index != 0, |previous: u64| {
            previous.checked_add(1) != Some(step_index)
        }) {
            // Preserve compatibility diagnostics for deliberately omitted
            // metadata/malformed prefixes, while the typed proof fails closed.
            result.complete = false;
        }
        previous_step = Some(step_index);
        if rec
            .truncated_fields
            .as_ref()
            .is_some_and(|fields| !fields.is_empty())
        {
            result.incomplete(
                format!("line {}: truncated step fields, skipped", line.number),
                true,
            );
            continue;
        }
        if !matches!(rec.status.as_deref(), Some("DONE" | "ERROR")) {
            result.incomplete(
                format!(
                    "line {}: step is not a known terminal observation, skipped",
                    line.number
                ),
                true,
            );
            continue;
        }
        if rec.r#type.as_deref() == Some("CONVERSATION_HISTORY") {
            continue;
        }
        let role = match rec.source.as_deref() {
            Some("USER_EXPLICIT") => "user",
            Some("MODEL") => "assistant",
            Some("SYSTEM") => continue,
            _ => {
                result.complete = false;
                continue;
            }
        };
        if !matches!(
            rec.r#type.as_deref(),
            Some("USER_INPUT" | "PLANNER_RESPONSE" | "GENERIC")
        ) {
            result.incomplete(
                format!(
                    "line {}: missing or unknown conversational step type, skipped",
                    line.number
                ),
                true,
            );
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
            thinking
        } else {
            continue;
        };
        let timestamp = rec.created_at.as_deref().filter(|value| is_rfc3339(value));
        result.emit(
            sink,
            step_index,
            MessageEvent {
                session: None,
                seq: 0,
                native_id: "",
                parent_native_id: None,
                role,
                text,
                timestamp,
                is_sidechain: false,
                span: Some((line.start, line.end)),
            },
            deadline,
        )?;
    }
    if records == 0 {
        result.incomplete(
            "empty transcript does not establish a complete source".into(),
            false,
        );
    }
    result.diagnostic("antigravity session identity is unavailable in transcript bytes; directory context belongs to the caller".into());
    deadline.check()?;
    Ok(result)
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
                "transcript bytes contain no native session ID; the caller supplies verified source/session context",
                "SYSTEM/CONVERSATION_HISTORY and tool activity are not emitted as messages",
                "the additive conversation-sqlite-step-v1 parser is limited to the observed CLI 1.1.16 Step subset; the shared capability row still advertises the JSONL variant",
                "managed publication requires parse_source_with_steps.complete; truncated, nonterminal, missing or discontinuous step identity is incomplete",
                "conversation snapshots are bounded to 128 MiB, 250000 steps and 8 MiB per Step; SQLite database spans and unverified step timestamps stay unavailable",
                "loose encrypted or unknown protobuf conversation envelopes are unsupported; no readable-string extraction fallback",
            ],
        )
    }

    fn probe(&self, bytes: &[u8]) -> Result<ProbeResult, ProviderError> {
        if bytes.starts_with(protobuf::SQLITE_MAGIC) {
            return protobuf::probe_conversation_snapshot(bytes);
        }
        let text = std::str::from_utf8(bytes).map_err(|_| {
            ProviderError::AmbiguousVariant("unknown Antigravity snapshot encoding".into())
        })?;
        let text = text.strip_prefix('\u{feff}').unwrap_or(text);
        let sample: Vec<_> = text
            .lines()
            .enumerate()
            .filter(|(_, line)| !line.trim().is_empty())
            .take(SAMPLE_LINE_LIMIT)
            .collect();
        if sample.is_empty() {
            return Err(ProviderError::AmbiguousVariant(
                "empty input: no non-blank lines to probe".into(),
            ));
        }
        let mut matched = Vec::new();
        let mut unmatched = Vec::new();
        let mut json_lines = 0usize;
        let mut step_records = 0usize;
        let mut source_records = 0usize;
        for (index, line) in &sample {
            if line.len() as u64 > agent_session_grep_ports::STREAM_RECORD_MAX_BYTES {
                return Err(ProviderError::RecordTooLarge {
                    actual: line.len() as u64,
                    max: agent_session_grep_ports::STREAM_RECORD_MAX_BYTES,
                });
            }
            match serde_json::from_str::<serde_json::Value>(line) {
                Ok(value) => {
                    json_lines += 1;
                    if value
                        .get("step_index")
                        .and_then(serde_json::Value::as_u64)
                        .is_some()
                    {
                        step_records += 1;
                        if value
                            .get("source")
                            .and_then(serde_json::Value::as_str)
                            .is_some()
                        {
                            source_records += 1;
                        }
                    }
                }
                Err(_) => unmatched.push(format!("line {}: not valid JSON", index + 1)),
            }
        }
        if step_records == 0 {
            return Err(ProviderError::AmbiguousVariant(
                "no valid Antigravity step identity in the sample".into(),
            ));
        }
        matched.push(format!("{json_lines} sampled lines are valid JSON"));
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
            variant_id: VARIANT_ID.into(),
            confidence,
            matched_evidence: matched,
            unmatched_evidence: unmatched,
        })
    }

    fn probe_source(&self, source: &dyn ReadOnlySource) -> Result<ProbeResult, ProviderError> {
        if source_is_sqlite(source)? {
            let bytes = agent_session_grep_ports::read_bounded_source(
                source,
                agent_session_grep_ports::SQLITE_MAX_SOURCE_BYTES,
            )
            .map_err(redact_io)?;
            self.probe(&bytes)
        } else {
            let bytes = agent_session_grep_ports::read_probe_sample(
                source,
                agent_session_grep_ports::STREAM_RECORD_MAX_BYTES,
            )
            .map_err(redact_io)?;
            self.probe(&bytes)
        }
    }

    fn parse(
        &self,
        bytes: &[u8],
        sink: &mut dyn CanonicalEventSink,
    ) -> Result<ParseReport, ProviderError> {
        Ok(self.parse_with_steps(bytes, sink)?.report)
    }

    fn parse_source(
        &self,
        source: &dyn ReadOnlySource,
        sink: &mut dyn CanonicalEventSink,
    ) -> Result<ParseReport, ProviderError> {
        Ok(self.parse_source_with_steps(source, sink)?.report)
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
        assert_eq!(sink.events[0].1, "");
        assert_eq!(sink.events[0].2, "user");
        assert_eq!(sink.events[0].3, "build the project");
        assert_eq!(sink.events[1].0, 1);
        assert_eq!(sink.events[1].1, "");
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

    #[test]
    fn parse_passes_noise_shaped_user_text_through_verbatim() {
        // 钉住测试：Antigravity transcript.jsonl 没有 system-reminder / AGENTS.md /
        // 环境上下文等注入概念（USER_EXPLICIT 的 content 就是用户原文；系统
        // 注入走 source:"SYSTEM" 的记录类型，已在类型层排除）。形似噪声的文本
        // 必须逐字透传，防止将来把别家格式的过滤规则盲目搬来造成 silent drift。
        let adapter = AntigravityAdapter::new();
        let fixture = r##"{"step_index":0,"source":"USER_EXPLICIT","type":"USER_INPUT","status":"DONE","content":"<system-reminder>reminder text</system-reminder>"}
{"step_index":1,"source":"USER_EXPLICIT","type":"USER_INPUT","status":"DONE","content":"# AGENTS.md instructions"}
"##;
        let mut sink = RecordingSink { events: Vec::new() };
        let report = adapter.parse(fixture.as_bytes(), &mut sink).unwrap();
        assert_eq!(report.committed, 2);
        assert_eq!(report.skipped, 0);
        assert_eq!(
            sink.events[0].3,
            "<system-reminder>reminder text</system-reminder>"
        );
        assert_eq!(sink.events[1].3, "# AGENTS.md instructions");
    }
}
