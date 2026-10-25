//! DeepSeek Harness v4 append-only session logs in concatenated Zstandard frames.
//!
//! Schema facts are pinned to official commit
//! `1517a4dbca0a2789ff1d41ba439600f8547d23fa`. This adapter reads captured bytes
//! only: it never opens a profile, translates old generations, repairs a file,
//! synthesizes turn closers, or determines source deletion. Discovery must select
//! the highest canonical generation under the actual `~/.dsh` deployment root.
//!
//! Complete user/assistant records are historical transcript evidence, including
//! surface replacement records. This is not the harness's live-surface replay.
//! Compressed bytes have no truthful per-message contiguous span, so spans are
//! absent. A torn final frame returns only complete decoded lines and explicitly
//! marks the report incomplete; other decoding/structural errors reject staging.

use agent_session_grep_ports::{
    AdapterManifest, CanonicalEventSink, Confidence, MessageEvent, MetadataResolution, ParseReport,
    ProbeResult, ProviderAdapter, ProviderError, ReadOnlySource, STREAM_RECORD_MAX_BYTES,
    SliceSource, manifest_for,
};
use serde_json::Value;
use std::io::{self, BufRead, BufReader, Read};
use time::OffsetDateTime;

pub const PROVIDER_ID: &str = "deepseek-harness";
pub const VARIANT_ID: &str = "deepseek-harness/session-jsonl-zstd-v4";
pub const SESSION_FORMAT_VERSION: u64 = 4;
pub const MAX_COMPRESSED_BYTES: u64 = 128 * 1024 * 1024;
pub const MAX_DECOMPRESSED_BYTES: u64 = 256 * 1024 * 1024;
pub const MAX_WINDOW_LOG: u32 = 23;
const MAX_DIAGNOSTICS: usize = 32;
const JS_MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
const MAX_UTC_MILLIS: u64 = 253_402_300_799_999;
const ZSTD_MAGIC: [u8; 4] = [0x28, 0xb5, 0x2f, 0xfd];

/// Limits may be tightened for a bounded caller or synthetic tests, never raised
/// above the adapter's supported defaults. The window limit bounds native
/// decoder allocation independently of decoded record and total output sizes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DshLimits {
    pub compressed_bytes: u64,
    pub decompressed_bytes: u64,
    pub record_bytes: u64,
    pub window_log: u32,
}
impl Default for DshLimits {
    fn default() -> Self {
        Self {
            compressed_bytes: MAX_COMPRESSED_BYTES,
            decompressed_bytes: MAX_DECOMPRESSED_BYTES,
            record_bytes: STREAM_RECORD_MAX_BYTES,
            window_log: MAX_WINDOW_LOG,
        }
    }
}
impl DshLimits {
    fn validate(self) -> Result<Self, ProviderError> {
        if self.compressed_bytes == 0
            || self.compressed_bytes > MAX_COMPRESSED_BYTES
            || self.decompressed_bytes == 0
            || self.decompressed_bytes > MAX_DECOMPRESSED_BYTES
            || self.record_bytes == 0
            || self.record_bytes > STREAM_RECORD_MAX_BYTES
            || !(10..=MAX_WINDOW_LOG).contains(&self.window_log)
        {
            return Err(fatal("invalid DSH limits"));
        }
        Ok(self)
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct DeepSeekHarnessAdapter {
    limits: DshLimits,
}
impl DeepSeekHarnessAdapter {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn with_limits(limits: DshLimits) -> Result<Self, ProviderError> {
        Ok(Self {
            limits: limits.validate()?,
        })
    }
}

fn fatal(reason: &str) -> ProviderError {
    ProviderError::StructuralFatal(reason.into())
}
fn note(report: &mut ParseReport, line: usize, reason: &str) {
    if report.diagnostics.len() < MAX_DIAGNOSTICS {
        report.diagnostics.push(format!("line {line}: {reason}"));
    }
}
fn nonblank(value: &Value) -> Option<&str> {
    value.as_str().filter(|text| !text.trim().is_empty())
}
fn safe_integer(value: &Value) -> Option<u64> {
    value.as_u64().filter(|value| *value <= JS_MAX_SAFE_INTEGER)
}
fn timestamp(value: &Value) -> Option<String> {
    let milliseconds = safe_integer(value).filter(|value| *value <= MAX_UTC_MILLIS)?;
    let instant = OffsetDateTime::from_unix_timestamp((milliseconds / 1000) as i64).ok()?;
    Some(format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        instant.year(),
        instant.month() as u8,
        instant.day(),
        instant.hour(),
        instant.minute(),
        instant.second(),
        milliseconds % 1000,
    ))
}

struct Header {
    id: String,
    cwd: Option<String>,
    sidechain: bool,
}
fn header(row: &Value) -> Result<Header, ProviderError> {
    if row.get("type").and_then(Value::as_str) != Some("session") {
        return Err(ProviderError::AmbiguousVariant(
            "DSH compressed source requires a first session header".into(),
        ));
    }
    let version = row
        .get("version")
        .and_then(safe_integer)
        .ok_or_else(|| fatal("invalid DSH session version"))?;
    if version != SESSION_FORMAT_VERSION {
        return Err(ProviderError::AmbiguousVariant(format!(
            "unsupported DSH session format version {version}; adapter supports 4"
        )));
    }
    let id = row
        .get("id")
        .and_then(nonblank)
        .ok_or_else(|| fatal("missing or invalid DSH session identity"))?;
    if row.get("createdAt").and_then(timestamp).is_none()
        || !row.get("isSeeded").is_some_and(Value::is_boolean)
    {
        return Err(fatal("invalid DSH session creation metadata"));
    }
    let cwd = match row.get("cwd") {
        None => None,
        Some(Value::String(value)) => (!value.trim().is_empty()).then(|| value.clone()),
        _ => return Err(fatal("invalid DSH working-directory metadata")),
    };
    if row
        .get("parentSession")
        .is_some_and(|value| nonblank(value).is_none())
        || row
            .get("agentPreset")
            .is_some_and(|value| nonblank(value).is_none())
    {
        return Err(fatal("invalid DSH lineage or preset metadata"));
    }
    let depth = row
        .get("delegationDepth")
        .and_then(safe_integer)
        .ok_or_else(|| fatal("missing or invalid DSH delegation depth"))?;
    let origin = match row.get("origin") {
        None => false,
        Some(Value::String(value)) if value == "subagent" => true,
        _ => return Err(fatal("unsupported DSH session origin")),
    };
    Ok(Header {
        id: id.into(),
        cwd,
        sidechain: origin || depth > 0,
    })
}

/// Fact vocabulary transcribed from the pinned public persistence catalog;
/// this table is not a copy of the upstream parser or generated validator.
fn known_log_record(kind: &str) -> bool {
    matches!(
        kind,
        "agent-preset/selected"
            | "agent/inbox/spliced"
            | "approval/asked"
            | "approval/decided"
            | "approval/policy"
            | "assistant/attempt"
            | "command/done"
            | "command/run"
            | "compaction/end"
            | "compaction/prune"
            | "compaction/start"
            | "compaction/summary"
            | "deliverables/presented"
            | "feedback/message-delete"
            | "feedback/message-put"
            | "feedback/record"
            | "goal/change"
            | "hook/invoked"
            | "hook/result"
            | "job/registered"
            | "job/settled"
            | "llm/retry"
            | "llm/retry-started"
            | "model/selection"
            | "permission/preset"
            | "plan/mode"
            | "request/context"
            | "request/header"
            | "sandbox/mode"
            | "schedule/change"
            | "session-log-deepseek/delivery-accepted"
            | "session/end-seed"
            | "session/title"
            | "session/title-llm-request"
            | "step/end"
            | "step/start"
            | "subagent/catalog"
            | "subagent/descriptor"
            | "subagent/model-selection-policy"
            | "team/member"
            | "team/message/delivered"
            | "team/message/queued"
            | "team/task"
            | "todo/write"
            | "tool-workflow/agent-end"
            | "tool-workflow/agent-start"
            | "tool-workflow/run-end"
            | "tool-workflow/run-start"
            | "tool/call"
            | "tool/ptc-dispatch"
            | "tool/ptc-dispatch-start"
            | "turn/end"
            | "turn/start"
            | "web/deepseek-search-llm-request"
            | "working-directory/change"
            | "workspace/changes"
    )
}
fn surface_record(kind: &str) -> bool {
    matches!(
        kind,
        "user/message"
            | "assistant/message"
            | "system/message"
            | "developer/message"
            | "tool/result"
    )
}

/// Validate the recorded operation without rewriting original historical
/// messages. Cited sequence ranges stay compressed; no expansion can allocate
/// in proportion to a caller-supplied numeric range.
fn surface(row: &Value, seq: u64, kind: &str) -> Result<bool, ProviderError> {
    let replace = match row.get("surfaceOp") {
        Some(Value::String(op)) if op == "append" => false,
        Some(op) if op.is_object() && op.get("op").and_then(Value::as_str) == Some("replace") => {
            let start = op.get("startSeq").and_then(safe_integer);
            let end = op.get("endSeq").and_then(safe_integer);
            match (start, end) {
                (Some(start), Some(end)) if start <= end && end < seq => true,
                _ => return Err(fatal("invalid DSH surface replacement range")),
            }
        }
        _ => return Err(fatal("missing or unsupported DSH surface operation")),
    };
    if let Some(value) = row.get("sourceEventSeqs") {
        if kind == "assistant/message" {
            return Err(fatal("DSH assistant source references are forbidden"));
        }
        let sources = value
            .as_array()
            .filter(|values| !values.is_empty())
            .ok_or_else(|| fatal("invalid DSH source-event references"))?;
        for source in sources {
            if let Some(value) = safe_integer(source) {
                if value >= seq {
                    return Err(fatal("DSH source-event reference is not earlier"));
                }
            } else if let Some(range) = source.as_array().filter(|range| range.len() == 2) {
                match (safe_integer(&range[0]), safe_integer(&range[1])) {
                    (Some(start), Some(end)) if start <= end && end < seq => {}
                    _ => return Err(fatal("invalid DSH source-event range")),
                }
            } else {
                return Err(fatal("invalid DSH source-event reference type"));
            }
        }
    }
    Ok(replace)
}
fn message<'a>(data: &'a Value, role: &str) -> Result<(&'a str, String), ProviderError> {
    let value = if role == "user" {
        data
    } else {
        data.get("message")
            .ok_or_else(|| fatal("missing DSH assembled assistant message"))?
    };
    if value.get("role").and_then(Value::as_str) != Some(role) {
        return Err(fatal("invalid DSH message role"));
    }
    let id = value
        .get("id")
        .and_then(nonblank)
        .ok_or_else(|| fatal("missing or invalid DSH native message identity"))?;
    let source = value
        .get("source")
        .filter(|source| source.is_object())
        .ok_or_else(|| fatal("missing or invalid DSH message source"))?;
    let kind = source
        .get("kind")
        .and_then(nonblank)
        .ok_or_else(|| fatal("invalid DSH message source kind"))?;
    if role == "assistant"
        && (kind != "model"
            || source.get("provider").and_then(nonblank).is_none()
            || source.get("model").and_then(nonblank).is_none())
    {
        return Err(fatal("invalid DSH model message attribution"));
    }
    if role == "assistant" {
        if !data.get("stream").is_some_and(Value::is_array)
            || data
                .get("interrupted")
                .is_some_and(|value| value != &Value::Bool(true))
        {
            return Err(fatal("invalid DSH assistant settlement metadata"));
        }
        for field in ["turn", "step"] {
            if data.get(field).and_then(safe_integer).is_none() {
                return Err(fatal("invalid DSH assistant turn or step"));
            }
        }
    }
    let blocks = value
        .get("content")
        .and_then(Value::as_array)
        .ok_or_else(|| fatal("missing or invalid DSH message content blocks"))?;
    let mut text = Vec::new();
    for block in blocks {
        match block.get("type").and_then(Value::as_str) {
            Some("text") => text.push(
                block
                    .get("text")
                    .and_then(Value::as_str)
                    .ok_or_else(|| fatal("invalid DSH text block"))?,
            ),
            Some(
                "reasoning" | "image" | "file" | "tool-call" | "tool-addition" | "tool-removal",
            ) => {}
            _ => {
                return Err(ProviderError::AmbiguousVariant(
                    "unsupported DSH content block".into(),
                ));
            }
        }
    }
    Ok((id, text.join("\n")))
}

impl ProviderAdapter for DeepSeekHarnessAdapter {
    fn provider_id(&self) -> &str {
        PROVIDER_ID
    }
    fn manifest(&self) -> AdapterManifest {
        manifest_for(
            PROVIDER_ID,
            Some(1),
            &[
                "v4 concatenated zstd only; historical translation and generation selection belong to discovery",
                "decoded output is capped at 256 MiB, records at 8 MiB, input at 128 MiB and decoder window at 8 MiB",
                "torn final frames return only complete lines with an explicitly incomplete report",
                "historical user/assistant records are indexed; this is not current model-surface replay",
                "compressed records have no contiguous original-byte message spans",
                "tool/activity and usage projections are not emitted by this adapter",
                "local parsing is not evidence of source deletion, actual host loading or native acceptance",
            ],
        )
    }
    fn probe(&self, bytes: &[u8]) -> Result<ProbeResult, ProviderError> {
        if !bytes.starts_with(&ZSTD_MAGIC) {
            return Ok(ProbeResult {
                variant_id: VARIANT_ID.into(),
                confidence: Confidence::Ambiguous,
                matched_evidence: Vec::new(),
                unmatched_evidence: vec!["missing standard DSH zstd frame prefix".into()],
            });
        }
        self.probe_source(&SliceSource::new(bytes))
    }
    fn probe_source(&self, source: &dyn ReadOnlySource) -> Result<ProbeResult, ProviderError> {
        let mut records = Records::new(source, self.limits)?;
        let Some(record) = records.next()? else {
            return Err(ProviderError::AmbiguousVariant(
                "missing complete DSH session header".into(),
            ));
        };
        let row: Value =
            serde_json::from_slice(record).map_err(|_| fatal("invalid DSH session header JSON"))?;
        header(&row)?;
        Ok(ProbeResult {
            variant_id: VARIANT_ID.into(),
            confidence: Confidence::High,
            matched_evidence: vec![
                "zstd-decoded session header with version 4, native identity and creation metadata"
                    .into(),
            ],
            unmatched_evidence: vec!["body/frame integrity is checked by full parsing".into()],
        })
    }
    fn parse(
        &self,
        bytes: &[u8],
        sink: &mut dyn CanonicalEventSink,
    ) -> Result<ParseReport, ProviderError> {
        self.parse_source(&SliceSource::new(bytes), sink)
    }
    fn parse_source(
        &self,
        source: &dyn ReadOnlySource,
        sink: &mut dyn CanonicalEventSink,
    ) -> Result<ParseReport, ProviderError> {
        let mut records = Records::new(source, self.limits)?;
        let first = records
            .next()?
            .ok_or_else(|| fatal("missing complete DSH session header"))?;
        let row: Value =
            serde_json::from_slice(first).map_err(|_| fatal("invalid DSH session header JSON"))?;
        let session = header(&row)?;
        let mut report = ParseReport {
            session_native_id: Some(session.id.clone()),
            ..ParseReport::default()
        };
        report.session_observation.provider_session_id = MetadataResolution::Resolved(session.id);
        if let Some(cwd) = session.cwd {
            report.session_observation.original_working_directory =
                MetadataResolution::Resolved(cwd);
            report.session_observation.pair_observed = true;
        }
        let mut next_seq = 0_u64;
        let mut ordinal = 0_u32;
        while let Some(bytes) = records.next()? {
            let row: Value = serde_json::from_slice(bytes)
                .map_err(|_| fatal("invalid JSON in complete DSH record"))?;
            let kind = row
                .get("type")
                .and_then(nonblank)
                .ok_or_else(|| fatal("missing or invalid DSH record type"))?;
            if row.get("seq").and_then(safe_integer) != Some(next_seq) {
                return Err(fatal("DSH event sequence is not contiguous"));
            }
            let time = row
                .get("time")
                .and_then(timestamp)
                .ok_or_else(|| fatal("invalid or out-of-range DSH event time"))?;
            next_seq = next_seq
                .checked_add(1)
                .ok_or_else(|| fatal("DSH event sequence overflow"))?;
            let data = row
                .get("data")
                .ok_or_else(|| fatal("missing DSH event data"))?;
            if row
                .get("ignorable")
                .is_some_and(|value| value != &Value::Bool(true))
            {
                return Err(fatal("invalid DSH ignorable marker"));
            }
            let line = records.number - 1;
            let known = surface_record(kind) || known_log_record(kind) || kind == "image/offload";
            if !known && kind != "session" {
                if row.get("ignorable") == Some(&Value::Bool(true)) {
                    note(
                        &mut report,
                        line,
                        "unknown explicitly ignorable event retained only in source bytes",
                    );
                    continue;
                }
                return Err(ProviderError::AmbiguousVariant(
                    "unknown required DSH event".into(),
                ));
            }
            if !data.is_object() {
                return Err(fatal("invalid DSH known event data"));
            }
            if surface_record(kind) {
                if surface(&row, next_seq - 1, kind)? {
                    note(
                        &mut report,
                        line,
                        "surface replacement retained as historical evidence; live-surface replay is not performed",
                    );
                }
            } else if row.get("surfaceOp").is_some() || row.get("sourceEventSeqs").is_some() {
                return Err(fatal("DSH non-surface record carries surface metadata"));
            }
            match kind {
                "user/message" | "assistant/message" => {
                    let role = if kind == "user/message" {
                        "user"
                    } else {
                        "assistant"
                    };
                    let (id, text) = message(data, role)?;
                    sink.emit_message(MessageEvent {
                        session: None,
                        seq: ordinal,
                        native_id: id,
                        parent_native_id: None,
                        role,
                        text: &text,
                        timestamp: Some(&time),
                        is_sidechain: session.sidechain,
                        span: None,
                    })
                    .map_err(|_| ProviderError::Io("DSH message sink unavailable".into()))?;
                    ordinal = ordinal
                        .checked_add(1)
                        .ok_or_else(|| fatal("DSH message ordinal overflow"))?;
                    report.committed += 1;
                }
                "system/message" | "developer/message" | "tool/result" => {}
                "image/offload" => {
                    return Err(ProviderError::AmbiguousVariant(
                        "DSH image-offload projection is not implemented".into(),
                    ));
                }
                "session" => return Err(fatal("DSH source contains another session header")),
                kind if known_log_record(kind) => {}
                _ if row.get("ignorable") == Some(&Value::Bool(true)) => {
                    note(
                        &mut report,
                        line,
                        "unknown explicitly ignorable event retained only in source bytes",
                    );
                }
                _ => {
                    return Err(ProviderError::AmbiguousVariant(
                        "unknown required DSH event".into(),
                    ));
                }
            }
        }
        if records.torn_tail() {
            report.skipped += 1;
            note(
                &mut report,
                records.number,
                "torn final zstd frame: only complete decoded lines retained; source incomplete, never a deletion signal",
            );
        }
        Ok(report)
    }
}

/// The capture is the authority for length; a short/erroring reader is source
/// I/O failure, not a recoverable compressed tail. No read escapes that range.
struct Capture<'a> {
    reader: Box<dyn BufRead + Send + 'a>,
    expected: u64,
    consumed: u64,
    failed: bool,
}
impl Read for Capture<'_> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let available = self.fill_buf()?;
        let count = available.len().min(output.len());
        output[..count].copy_from_slice(&available[..count]);
        self.consume(count);
        Ok(count)
    }
}
impl BufRead for Capture<'_> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        if self.consumed == self.expected {
            return Ok(&[]);
        }
        let available = match self.reader.fill_buf() {
            Ok(available) => available,
            Err(_) => {
                self.failed = true;
                return Err(io::Error::other("DSH captured source unavailable"));
            }
        };
        if available.is_empty() {
            self.failed = true;
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "DSH captured range is short",
            ));
        }
        let count = available
            .len()
            .min((self.expected - self.consumed) as usize);
        Ok(&available[..count])
    }
    fn consume(&mut self, count: usize) {
        self.reader.consume(count);
        self.consumed += count as u64;
    }
}

#[derive(Clone, Copy)]
enum DecodeFailure {
    Input,
    Corrupt,
    Limit(u64),
}
struct Decoded<'a> {
    decoder: zstd::stream::read::Decoder<'static, Capture<'a>>,
    output: u64,
    max_output: u64,
    torn: bool,
    finished: bool,
    failure: Option<DecodeFailure>,
}
impl Read for Decoded<'_> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if self.finished || output.is_empty() {
            return Ok(0);
        }
        let count = output
            .len()
            .min((self.max_output - self.output + 1) as usize);
        match self.decoder.read(&mut output[..count]) {
            Ok(read) => {
                self.output += read as u64;
                if self.output > self.max_output {
                    self.failure = Some(DecodeFailure::Limit(self.output));
                    return Err(io::Error::other("DSH decoded output limit exceeded"));
                }
                self.finished = read == 0;
                Ok(read)
            }
            Err(error) => {
                let capture = self.decoder.get_ref();
                if !capture.failed
                    && error.kind() == io::ErrorKind::UnexpectedEof
                    && capture.consumed == capture.expected
                {
                    self.torn = true;
                    self.finished = true;
                    Ok(0)
                } else {
                    self.failure = Some(if capture.failed {
                        DecodeFailure::Input
                    } else {
                        DecodeFailure::Corrupt
                    });
                    Err(io::Error::other("DSH frame decode failed"))
                }
            }
        }
    }
}

/// Format-owned record reader: unlike the generic JSONL reader it must retain
/// line termination, distinguish a torn compressed tail from capture failure,
/// and enforce the separate cumulative decoded budget.
struct Records<'a> {
    reader: BufReader<Decoded<'a>>,
    line: Vec<u8>,
    number: usize,
    max_record: u64,
}
impl<'a> Records<'a> {
    fn new(source: &'a dyn ReadOnlySource, limits: DshLimits) -> Result<Self, ProviderError> {
        if source.len() > limits.compressed_bytes {
            return Err(ProviderError::SourceTooLarge {
                actual: source.len(),
                max: limits.compressed_bytes,
            });
        }
        let input = Capture {
            reader: source
                .open()
                .map_err(|_| ProviderError::Io("DSH captured source unavailable".into()))?,
            expected: source.len(),
            consumed: 0,
            failed: false,
        };
        let mut decoder = zstd::stream::read::Decoder::with_buffer(input)
            .map_err(|_| ProviderError::Io("DSH decoder initialization failed".into()))?;
        decoder
            .window_log_max(limits.window_log)
            .map_err(|_| fatal("DSH decoder window limit could not be set"))?;
        Ok(Self {
            reader: BufReader::with_capacity(
                64 * 1024,
                Decoded {
                    decoder,
                    output: 0,
                    max_output: limits.decompressed_bytes,
                    torn: false,
                    finished: false,
                    failure: None,
                },
            ),
            line: Vec::new(),
            number: 1,
            max_record: limits.record_bytes,
        })
    }
    fn torn_tail(&self) -> bool {
        self.reader.get_ref().torn
    }
    fn next(&mut self) -> Result<Option<&[u8]>, ProviderError> {
        self.line.clear();
        loop {
            let available = match self.reader.fill_buf() {
                Ok(available) => available,
                Err(_) => {
                    return Err(match self.reader.get_ref().failure {
                        Some(DecodeFailure::Input) => {
                            ProviderError::Io("DSH captured source unavailable or changed".into())
                        }
                        Some(DecodeFailure::Limit(actual)) => ProviderError::SourceTooLarge {
                            actual,
                            max: self.reader.get_ref().max_output,
                        },
                        _ => fatal("DSH compressed frame is corrupt or unsupported"),
                    });
                }
            };
            if available.is_empty() {
                if !self.line.is_empty() && !self.torn_tail() {
                    return Err(fatal(
                        "complete DSH frame contains an unterminated JSONL record",
                    ));
                }
                // A fragment without LF is not a complete recovered row, even
                // if its bytes happen to parse as JSON. Never create it.
                return Ok(None);
            }
            let newline = available.iter().position(|byte| *byte == b'\n');
            let count = newline.map_or(available.len(), |position| position + 1);
            let actual = self.line.len() as u64 + count as u64;
            if actual > self.max_record {
                return Err(ProviderError::RecordTooLarge {
                    actual,
                    max: self.max_record,
                });
            }
            self.line.extend_from_slice(&available[..count]);
            self.reader.consume(count);
            if newline.is_some() {
                let number = self.number;
                self.number += 1;
                let line = self.line.strip_suffix(b"\n").unwrap_or(&self.line);
                let line = line.strip_suffix(b"\r").unwrap_or(line);
                let line = if number == 1 {
                    line.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(line)
                } else {
                    line
                };
                if line.iter().all(u8::is_ascii_whitespace) {
                    return Err(fatal("blank record in committed DSH JSONL"));
                }
                return Ok(Some(line));
            }
        }
    }
}
