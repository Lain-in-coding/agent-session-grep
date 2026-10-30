//! Pure staging for an already-selected, caller-proven managed source.
//!
//! Source acquisition, logical SQLite Backup proof, canonical authority,
//! auxiliary metadata permission and publication belong to the caller. This
//! module never discovers a path or writes source/control/catalog state. One
//! original deadline covers every probe, source read, parse and sink emission.
//! Synchronous calls are checked on return; they cannot be forcibly preempted.

use agent_session_grep_application::{
    AppError, StagedBatch, select_and_stage_source, stage_source_with_parser,
};
use agent_session_grep_domain::DomainError;
use agent_session_grep_ports::{
    AdapterManifest, CanonicalEventSink, MessageEvent, ParseReport, PortError, PortResult,
    ProbeResult, ProviderAdapter, ProviderError, ReadOnlySource, SQLITE_MAX_SOURCE_BYTES,
    STREAM_RECORD_MAX_BYTES, SearchProvider, ToolActivityEvent, UsageEvent, read_bounded_source,
};
use agent_session_grep_provider_antigravity::{
    AntigravityAdapter, AntigravityObservation, AntigravitySourceFormat, CONVERSATION_VARIANT_ID,
    TRANSCRIPT_VARIANT_ID,
};
use agent_session_grep_provider_claude::ClaudeCodeAdapter;
use agent_session_grep_provider_codex::CodexAdapter;
use agent_session_grep_provider_dsh::{
    DeepSeekHarnessAdapter, MAX_COMPRESSED_BYTES, MAX_DECOMPRESSED_BYTES,
};
use agent_session_grep_provider_workbuddy::WorkBuddyAdapter;
use agent_session_grep_provider_zcode::{
    MAX_DECODED_BYTES, MAX_SQLITE_BYTES, VARIANT_ID as ZCODE_VARIANT_ID, ZCodeAdapter,
};
use std::{
    io::{self, BufRead, Read},
    sync::atomic::{AtomicBool, Ordering},
    time::Instant,
};

const READ_CHUNK_BYTES: usize = 64 * 1024;
const DEADLINE_MESSAGE: &str = "managed source parse deadline exceeded";

/// The container actually parsed. Never apply JSONL tail health to SQLite/zstd.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceFormat {
    Jsonl,
    Sqlite,
    ZstdJsonl,
}

/// Native input/allocation limits; None is not a whole-source buffering grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceInputLimits {
    /// Whole input cap, where the provider has one (ZCode or compressed DSH).
    pub max_source_bytes: Option<u64>,
    /// Conditional SQLite cap for a provider that also accepts streamed JSONL.
    pub max_sqlite_bytes: Option<u64>,
    pub max_record_bytes: Option<u64>,
    /// Separately bounded retained graph or decompressed stream.
    pub max_decoded_bytes: Option<u64>,
}

/// Only the six selected Beta source parsers are routed here. This is not a
/// second discovery/capability registry; canonical spellings use the shared one.
pub fn input_limits(provider: &str) -> Result<SourceInputLimits, AppError> {
    let provider = canonical_provider(provider)?;
    Ok(match provider {
        "zcode" => SourceInputLimits {
            max_source_bytes: Some(MAX_SQLITE_BYTES),
            max_sqlite_bytes: None,
            max_record_bytes: Some(STREAM_RECORD_MAX_BYTES),
            max_decoded_bytes: Some(MAX_DECODED_BYTES),
        },
        "deepseek-harness" => SourceInputLimits {
            max_source_bytes: Some(MAX_COMPRESSED_BYTES),
            max_sqlite_bytes: None,
            max_record_bytes: Some(STREAM_RECORD_MAX_BYTES),
            max_decoded_bytes: Some(MAX_DECOMPRESSED_BYTES),
        },
        "antigravity" => SourceInputLimits {
            max_source_bytes: None,
            max_sqlite_bytes: Some(SQLITE_MAX_SOURCE_BYTES),
            max_record_bytes: Some(STREAM_RECORD_MAX_BYTES),
            max_decoded_bytes: None,
        },
        _ => SourceInputLimits {
            max_source_bytes: None,
            max_sqlite_bytes: None,
            max_record_bytes: Some(STREAM_RECORD_MAX_BYTES),
            max_decoded_bytes: None,
        },
    })
}

/// Why a successfully parsed prefix is not a complete content observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IncompleteReason {
    InsufficientFormatEvidence,
    UnsupportedRecord,
    NativeObservationIncomplete,
    SkippedRecords,
    CapturedRangeNotConsumed,
}

/// Sealed evidence from this staging call; callers cannot construct a grant.
///
/// Content completeness is separate from root discovery, auxiliary metadata,
/// currentness, source identity/stability, authority and publication permission.
/// A complete value does not authorize any of those operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceCompleteness {
    format: SourceFormat,
    source_bytes: u64,
    incomplete: Option<IncompleteReason>,
    antigravity: Option<Box<AntigravityObservation>>,
}
impl SourceCompleteness {
    pub fn is_complete(&self) -> bool {
        self.incomplete.is_none()
    }
    pub fn format(&self) -> SourceFormat {
        self.format
    }
    pub fn source_bytes(&self) -> u64 {
        self.source_bytes
    }
    pub fn incomplete_reason(&self) -> Option<IncompleteReason> {
        self.incomplete
    }
    /// Includes exact StepEvidence and stored session observations from the
    /// SAME parse that produced staged messages; never a second inspection.
    pub fn antigravity(&self) -> Option<&AntigravityObservation> {
        self.antigravity.as_deref()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedSourceParse {
    pub staged: StagedBatch,
    pub variant_id: String,
    pub completeness: SourceCompleteness,
}

/// Stage an already-selected source using its original caller deadline.
///
/// Supported container validation happens in the provider. AG and ZCode use
/// their explicit original-deadline APIs, avoiding a full probe that resets a
/// default budget. Other adapters use Application's existing single-provider
/// selection rules and one full parse, with bounded source and sink wrappers.
/// Errors discard all staged messages/activities/usage and return no batch.
/// Incomplete evidence remains visible to the caller but must not be published.
pub fn stage(
    provider: &str,
    source: &dyn ReadOnlySource,
    original_end: Instant,
) -> Result<ManagedSourceParse, AppError> {
    let deadline = Deadline(original_end);
    deadline.check()?;
    let provider = canonical_provider(provider)?;
    let limits = input_limits(provider)?;
    let source = DeadlineSource::new(source, deadline)?.with_content_contract(provider);
    if let Some(max) = limits.max_source_bytes
        && source.len() > max
    {
        return Err(ProviderError::SourceTooLarge {
            actual: source.len(),
            max,
        }
        .into());
    }
    let parsed = match provider {
        "antigravity" => {
            let (staged, observed) = stage_source_with_parser(&source, |input, sink| {
                source.reset_parse_scan();
                let mut sink = DeadlineSink {
                    inner: sink,
                    deadline,
                };
                let result = AntigravityAdapter::new().parse_source_with_steps_deadline(
                    input,
                    &mut sink,
                    original_end,
                );
                deadline.check()?;
                let observed = result.map_err(redact_provider)?;
                Ok((observed.report.clone(), observed))
            })?;
            let (format, variant) = match observed.format {
                AntigravitySourceFormat::TranscriptJsonl => {
                    (SourceFormat::Jsonl, TRANSCRIPT_VARIANT_ID)
                }
                AntigravitySourceFormat::ConversationSqlite => {
                    (SourceFormat::Sqlite, CONVERSATION_VARIANT_ID)
                }
                AntigravitySourceFormat::ProtobufStep => return Err(unavailable()),
            };
            (staged, variant.to_owned(), format, Some(Box::new(observed)))
        }
        "zcode" => {
            let (staged, ()) = stage_source_with_parser(&source, |input, sink| {
                source.reset_parse_scan();
                let bytes = read_bounded_source(input, MAX_SQLITE_BYTES);
                deadline.check()?;
                let bytes = bytes.map_err(redact_provider)?;
                let mut sink = DeadlineSink {
                    inner: sink,
                    deadline,
                };
                let result =
                    ZCodeAdapter::new().parse_with_deadline(&bytes, &mut sink, original_end);
                deadline.check()?;
                Ok((result.map_err(redact_provider)?, ()))
            })?;
            (
                staged,
                ZCODE_VARIANT_ID.to_owned(),
                SourceFormat::Sqlite,
                None,
            )
        }
        "claude-code" => record_stage(
            &ClaudeCodeAdapter::new(),
            &source,
            deadline,
            SourceFormat::Jsonl,
        )?,
        "codex" => record_stage(&CodexAdapter::new(), &source, deadline, SourceFormat::Jsonl)?,
        "workbuddy" => record_stage(
            &WorkBuddyAdapter::new(),
            &source,
            deadline,
            SourceFormat::Jsonl,
        )?,
        "deepseek-harness" => record_stage(
            &DeepSeekHarnessAdapter::new(),
            &source,
            deadline,
            SourceFormat::ZstdJsonl,
        )?,
        _ => return Err(unavailable()),
    };
    deadline.check()?;
    if source.failed.load(Ordering::Relaxed) {
        return Err(ProviderError::Io(
            "managed source reader failed; staged events discarded".into(),
        )
        .into());
    }
    let (staged, variant_id, format, antigravity) = parsed;
    let incomplete = if antigravity
        .as_ref()
        .is_some_and(|observed| !observed.complete)
    {
        Some(IncompleteReason::NativeObservationIncomplete)
    } else if !source.strong_format.load(Ordering::Relaxed) {
        Some(IncompleteReason::InsufficientFormatEvidence)
    } else if !source.records_supported.load(Ordering::Relaxed) {
        Some(IncompleteReason::UnsupportedRecord)
    } else if staged.report.skipped != 0 {
        Some(IncompleteReason::SkippedRecords)
    } else if !source.full_parse_scan.load(Ordering::Relaxed) {
        Some(IncompleteReason::CapturedRangeNotConsumed)
    } else {
        None
    };
    Ok(ManagedSourceParse {
        staged,
        variant_id,
        completeness: SourceCompleteness {
            format,
            source_bytes: source.len(),
            incomplete,
            antigravity,
        },
    })
}

type Parsed = (
    StagedBatch,
    String,
    SourceFormat,
    Option<Box<AntigravityObservation>>,
);
fn record_stage(
    adapter: &dyn ProviderAdapter,
    source: &DeadlineSource<'_>,
    deadline: Deadline,
    format: SourceFormat,
) -> Result<Parsed, AppError> {
    let adapter = DeadlineAdapter {
        inner: adapter,
        source,
        deadline,
    };
    let result = select_and_stage_source(&[&adapter], source);
    deadline.check()?;
    let (staged, variant) = result.map_err(redact_app)?;
    Ok((staged, variant, format, None))
}
fn canonical_provider(provider: &str) -> Result<&'static str, AppError> {
    let provider = SearchProvider::parse(provider)
        .ok_or_else(unavailable)?
        .as_str();
    match provider {
        "claude-code" | "codex" | "workbuddy" | "zcode" | "deepseek-harness" | "antigravity" => {
            Ok(provider)
        }
        _ => Err(unavailable()),
    }
}
fn unavailable() -> AppError {
    DomainError::InvalidRequest("selected source format is unavailable for managed parsing".into())
        .into()
}
fn redact_app(error: AppError) -> AppError {
    match error {
        AppError::Provider(error) => redact_provider(error).into(),
        AppError::Domain(_) => unavailable(),
        other => other,
    }
}
fn redact_provider(error: ProviderError) -> ProviderError {
    match error {
        ProviderError::SourceTooLarge { .. } | ProviderError::RecordTooLarge { .. } => error,
        ProviderError::SourceChangedDuringRead(_) => {
            ProviderError::SourceChangedDuringRead("managed captured source changed".into())
        }
        ProviderError::AmbiguousVariant(_) => ProviderError::AmbiguousVariant(
            "selected source format is unsupported or ambiguous".into(),
        ),
        ProviderError::StructuralFatal(message) if message == DEADLINE_MESSAGE => {
            ProviderError::StructuralFatal(message)
        }
        ProviderError::StructuralFatal(_) => {
            ProviderError::StructuralFatal("managed source parser rejected staging".into())
        }
        ProviderError::Io(_) => {
            ProviderError::Io("managed source read or event emission failed".into())
        }
    }
}

#[derive(Clone, Copy)]
struct Deadline(Instant);
impl Deadline {
    fn check(self) -> Result<(), ProviderError> {
        if Instant::now() >= self.0 {
            Err(ProviderError::StructuralFatal(DEADLINE_MESSAGE.into()))
        } else {
            Ok(())
        }
    }
    fn io_check(self) -> io::Result<()> {
        self.check()
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, DEADLINE_MESSAGE))
    }
    fn port_check(self) -> PortResult<()> {
        self.check()
            .map_err(|_| PortError::SourceIo(DEADLINE_MESSAGE.into()))
    }
}

struct DeadlineSource<'a> {
    inner: &'a dyn ReadOnlySource,
    expected: u64,
    deadline: Deadline,
    full_parse_scan: AtomicBool,
    failed: AtomicBool,
    strong_format: AtomicBool,
    records_supported: AtomicBool,
    content_contract: Option<&'static str>,
}
impl<'a> DeadlineSource<'a> {
    fn new(inner: &'a dyn ReadOnlySource, deadline: Deadline) -> Result<Self, ProviderError> {
        deadline.check()?;
        let expected = inner.len();
        deadline.check()?;
        Ok(Self {
            inner,
            expected,
            deadline,
            full_parse_scan: AtomicBool::new(false),
            failed: AtomicBool::new(false),
            strong_format: AtomicBool::new(true),
            records_supported: AtomicBool::new(true),
            content_contract: None,
        })
    }
    fn with_content_contract(mut self, provider: &'static str) -> Self {
        // Legacy adapters ignore future record kinds without counting skips.
        // DSH decoding validates checksums only when present. Same-read gates
        // require the supported record kinds and checksummed standard frames.
        self.content_contract = matches!(
            provider,
            "claude-code" | "codex" | "workbuddy" | "deepseek-harness"
        )
        .then_some(provider);
        self
    }
    fn reset_parse_scan(&self) {
        // Probe-prefix reads must not establish the subsequent parse's coverage.
        self.full_parse_scan.store(false, Ordering::Relaxed);
        self.records_supported.store(true, Ordering::Relaxed);
    }
}
impl ReadOnlySource for DeadlineSource<'_> {
    fn len(&self) -> u64 {
        self.expected
    }
    fn open(&self) -> PortResult<Box<dyn BufRead + Send + '_>> {
        self.deadline.port_check()?;
        let opened = self.inner.open();
        self.deadline.port_check()?;
        let inner = opened.map_err(|_| {
            self.failed.store(true, Ordering::Relaxed);
            PortError::SourceIo("managed captured source unavailable".into())
        })?;
        Ok(Box::new(DeadlineReader {
            inner,
            source: self,
            consumed: 0,
            exposed: 0,
            failed: false,
            scan: self.content_contract.map(ContentScan::new),
        }))
    }
}
struct DeadlineReader<'a> {
    inner: Box<dyn BufRead + Send + 'a>,
    source: &'a DeadlineSource<'a>,
    consumed: u64,
    exposed: usize,
    failed: bool,
    scan: Option<ContentScan>,
}
impl DeadlineReader<'_> {
    fn failure(&mut self) {
        self.failed = true;
        self.source.failed.store(true, Ordering::Relaxed);
    }
    fn accept(&mut self, count: usize) -> io::Result<()> {
        let remaining = self.source.expected - self.consumed;
        if count as u64 > remaining || (count == 0 && remaining != 0) {
            self.failure();
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "managed captured source length changed",
            ));
        }
        self.consumed += count as u64;
        Ok(())
    }
}
impl Read for DeadlineReader<'_> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        self.source.deadline.io_check()?;
        if output.is_empty() {
            return Ok(0);
        }
        self.exposed = 0;
        if self.failed {
            return Err(io::Error::other(
                "managed captured source reader previously failed",
            ));
        }
        let chunk_length = output.len().min(READ_CHUNK_BYTES);
        let result = self.inner.read(&mut output[..chunk_length]);
        self.source.deadline.io_check()?;
        match result {
            Ok(read) => {
                self.accept(read)?;
                if let Some(scan) = &mut self.scan
                    && let Err(error) = scan.push(&output[..read], self.source.deadline)
                {
                    self.failure();
                    return Err(error);
                }
                Ok(read)
            }
            Err(_) => {
                self.failure();
                Err(io::Error::other("managed captured source read failed"))
            }
        }
    }
}
impl BufRead for DeadlineReader<'_> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        let deadline = self.source.deadline;
        deadline.io_check()?;
        if self.failed {
            return Err(io::Error::other(
                "managed captured source reader previously failed",
            ));
        }
        let result = self.inner.fill_buf();
        deadline.io_check()?;
        let available = match result {
            Ok(bytes) => bytes,
            Err(_) => {
                self.failed = true;
                self.source.failed.store(true, Ordering::Relaxed);
                return Err(io::Error::other("managed captured source read failed"));
            }
        };
        if (available.is_empty() && self.consumed != self.source.expected)
            || available.len() as u64 > self.source.expected - self.consumed
        {
            self.failed = true;
            self.source.failed.store(true, Ordering::Relaxed);
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "managed captured source length changed",
            ));
        }
        self.exposed = available.len().min(READ_CHUNK_BYTES);
        Ok(&available[..self.exposed])
    }
    fn consume(&mut self, count: usize) {
        // BufRead::consume cannot return an error. Latch failure so the next
        // read and final staging check fail, including consume-at-EOF callers.
        if self.source.deadline.check().is_err() || count > self.exposed {
            self.failure();
            return;
        }
        if let Some(scan) = &mut self.scan {
            let available = self.inner.fill_buf();
            if self.source.deadline.check().is_err() {
                self.failure();
                return;
            }
            match available {
                Ok(bytes) if count <= bytes.len() => {
                    if scan.push(&bytes[..count], self.source.deadline).is_err() {
                        self.failure();
                        return;
                    }
                }
                _ => {
                    self.failure();
                    return;
                }
            }
        }
        self.inner.consume(count);
        self.consumed += count as u64;
        self.exposed -= count;
        if self.source.deadline.check().is_err() {
            self.failure();
        }
    }
}
impl Drop for DeadlineReader<'_> {
    fn drop(&mut self) {
        if !self.failed && self.consumed == self.source.expected {
            let mut complete = true;
            if let Some(scan) = &mut self.scan {
                if scan.finish(self.source.deadline).is_err() {
                    self.source.failed.store(true, Ordering::Relaxed);
                    return;
                }
                if !scan.supported() {
                    self.source
                        .records_supported
                        .store(false, Ordering::Relaxed);
                }
                complete = scan.complete();
            }
            self.source
                .full_parse_scan
                .store(complete, Ordering::Relaxed);
        }
    }
}

/// Validation observes only bytes forwarded during this open, including the
/// provider's bounded probe. A later parse starts a new scan; neither gate
/// opens the source again or emits provider facts.
enum ContentScan {
    Records(RecordScan),
    DshFrames(DshFrameScan),
}
impl ContentScan {
    fn new(provider: &'static str) -> Self {
        if provider == "deepseek-harness" {
            Self::DshFrames(DshFrameScan::new())
        } else {
            Self::Records(RecordScan::new(provider))
        }
    }
    fn push(&mut self, bytes: &[u8], deadline: Deadline) -> io::Result<()> {
        match self {
            Self::Records(scan) => scan.push(bytes, deadline),
            Self::DshFrames(scan) => scan.push(bytes, deadline),
        }
    }
    fn finish(&mut self, deadline: Deadline) -> io::Result<()> {
        match self {
            Self::Records(scan) => scan.finish(deadline),
            Self::DshFrames(_) => deadline.io_check(),
        }
    }
    fn supported(&self) -> bool {
        match self {
            Self::Records(scan) => scan.supported,
            Self::DshFrames(_) => true,
        }
    }
    fn complete(&self) -> bool {
        match self {
            Self::Records(_) => true,
            Self::DshFrames(scan) => scan.complete(),
        }
    }
}

/// Only RFC 8878 frame boundaries/flags are inspected here, with four bytes of
/// scratch and no retained compressed/decompressed payload. The existing DSH
/// decoder checks block validity, its native limits and every checksum value.
/// Unsupported/skippable frames cannot stand in for the pinned checksummed
/// stream. A partial final frame remains incomplete even after decoded events.
struct DshFrameScan {
    part: DshFramePart,
    scratch: [u8; 4],
    seen_frame: bool,
}
#[derive(Clone, Copy)]
enum DshFramePart {
    Magic(usize),
    Descriptor,
    Header(usize),
    BlockHeader(usize),
    Block { remaining: usize, last: bool },
    Checksum(usize),
}
impl DshFrameScan {
    fn new() -> Self {
        Self {
            part: DshFramePart::Magic(0),
            scratch: [0; 4],
            seen_frame: false,
        }
    }
    fn complete(&self) -> bool {
        self.seen_frame && matches!(self.part, DshFramePart::Magic(0))
    }
    fn push(&mut self, mut bytes: &[u8], deadline: Deadline) -> io::Result<()> {
        while !bytes.is_empty() {
            deadline.io_check()?;
            match self.part {
                DshFramePart::Magic(filled) => {
                    let count = (4 - filled).min(bytes.len());
                    self.scratch[filled..filled + count].copy_from_slice(&bytes[..count]);
                    bytes = &bytes[count..];
                    self.part = if filled + count == 4 {
                        if self.scratch != [0x28, 0xb5, 0x2f, 0xfd] {
                            return Err(frame_error());
                        }
                        DshFramePart::Descriptor
                    } else {
                        DshFramePart::Magic(filled + count)
                    };
                }
                DshFramePart::Descriptor => {
                    let descriptor = bytes[0];
                    bytes = &bytes[1..];
                    if descriptor & 0x08 != 0 || descriptor & 0x04 == 0 {
                        return Err(frame_error());
                    }
                    let single_segment = descriptor & 0x20 != 0;
                    let content_size = match descriptor >> 6 {
                        0 => usize::from(single_segment),
                        1 => 2,
                        2 => 4,
                        _ => 8,
                    };
                    let dictionary = [0, 1, 2, 4][usize::from(descriptor & 3)];
                    self.part = DshFramePart::Header(
                        usize::from(!single_segment) + dictionary + content_size,
                    );
                }
                DshFramePart::Header(remaining) => {
                    let count = remaining.min(bytes.len());
                    bytes = &bytes[count..];
                    self.part = if count == remaining {
                        DshFramePart::BlockHeader(0)
                    } else {
                        DshFramePart::Header(remaining - count)
                    };
                }
                DshFramePart::BlockHeader(filled) => {
                    let count = (3 - filled).min(bytes.len());
                    self.scratch[filled..filled + count].copy_from_slice(&bytes[..count]);
                    bytes = &bytes[count..];
                    self.part = if filled + count == 3 {
                        let header = u32::from_le_bytes([
                            self.scratch[0],
                            self.scratch[1],
                            self.scratch[2],
                            0,
                        ]);
                        let size = (header >> 3) as usize;
                        let kind = (header >> 1) & 3;
                        if kind == 3 || size > 128 * 1024 {
                            return Err(frame_error());
                        }
                        DshFramePart::Block {
                            remaining: if kind == 1 { 1 } else { size },
                            last: header & 1 != 0,
                        }
                    } else {
                        DshFramePart::BlockHeader(filled + count)
                    };
                }
                DshFramePart::Block { remaining, last } => {
                    let count = remaining.min(bytes.len());
                    bytes = &bytes[count..];
                    self.part = if count == remaining {
                        if last {
                            DshFramePart::Checksum(4)
                        } else {
                            DshFramePart::BlockHeader(0)
                        }
                    } else {
                        DshFramePart::Block {
                            remaining: remaining - count,
                            last,
                        }
                    };
                }
                DshFramePart::Checksum(remaining) => {
                    let count = remaining.min(bytes.len());
                    bytes = &bytes[count..];
                    self.part = if count == remaining {
                        self.seen_frame = true;
                        DshFramePart::Magic(0)
                    } else {
                        DshFramePart::Checksum(remaining - count)
                    };
                }
            }
        }
        Ok(())
    }
}
fn frame_error() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "managed DSH source requires supported checksummed frames",
    )
}

/// A bounded top-level format gate, not a second provider transcript parser.
/// It never emits or canonicalizes facts, reads the source again, or changes
/// the forwarded bytes. Unknown required kinds cannot grant completeness.
struct RecordScan {
    provider: &'static str,
    line: Vec<u8>,
    first: bool,
    supported: bool,
}
#[derive(serde::Deserialize)]
struct RecordDiscriminator {
    #[serde(rename = "type")]
    kind: Option<String>,
    #[serde(default)]
    payload: Option<Box<serde_json::value::RawValue>>,
    #[serde(default)]
    message: Option<Box<serde_json::value::RawValue>>,
    #[serde(default)]
    content: Option<Box<serde_json::value::RawValue>>,
}
#[derive(serde::Deserialize)]
struct PayloadDiscriminator {
    #[serde(rename = "type")]
    kind: Option<String>,
    #[serde(default)]
    content: Option<Box<serde_json::value::RawValue>>,
}
#[derive(serde::Deserialize)]
struct MessageContent {
    #[serde(default)]
    content: Option<Box<serde_json::value::RawValue>>,
}
#[derive(serde::Deserialize)]
struct ContentBlock {
    #[serde(rename = "type")]
    kind: Option<String>,
    #[serde(default)]
    content: Option<Box<serde_json::value::RawValue>>,
}
/// Validate one block at a time; never retain an unbounded list of tiny parts.
struct ContentSeed {
    provider: &'static str,
    deadline: Deadline,
    depth: u32,
}
impl<'de> serde::de::DeserializeSeed<'de> for ContentSeed {
    type Value = bool;
    fn deserialize<D: serde::Deserializer<'de>>(self, deserializer: D) -> Result<bool, D::Error> {
        deserializer.deserialize_any(self)
    }
}
impl<'de> serde::de::Visitor<'de> for ContentSeed {
    type Value = bool;
    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a supported content shape")
    }
    fn visit_str<E: serde::de::Error>(self, _: &str) -> Result<bool, E> {
        Ok(true)
    }
    fn visit_unit<E: serde::de::Error>(self) -> Result<bool, E> {
        Ok(true)
    }
    fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut sequence: A) -> Result<bool, A::Error> {
        let mut supported = true;
        loop {
            self.deadline.check().map_err(serde::de::Error::custom)?;
            let Some(block) = sequence.next_element::<ContentBlock>()? else {
                break;
            };
            supported &= match (self.provider, block.kind.as_deref()) {
                (
                    "claude-code",
                    Some(
                        "text" | "thinking" | "redacted_thinking" | "tool_use" | "image"
                        | "document",
                    ),
                ) => true,
                ("claude-code", Some("tool_result")) => content_supported(
                    block.content.as_deref(),
                    self.provider,
                    self.deadline,
                    self.depth + 1,
                ),
                (
                    "codex",
                    Some("text" | "input_text" | "output_text" | "input_image" | "image"),
                ) => true,
                ("workbuddy", Some("text" | "image")) => true,
                _ => false,
            };
        }
        Ok(supported)
    }
    fn visit_map<A: serde::de::MapAccess<'de>>(self, mut map: A) -> Result<bool, A::Error> {
        let mut text = false;
        while let Some(key) = map.next_key::<String>()? {
            self.deadline.check().map_err(serde::de::Error::custom)?;
            if key == "text" {
                map.next_value::<String>()?;
                text = true;
            } else {
                map.next_value::<serde::de::IgnoredAny>()?;
            }
        }
        Ok(self.provider == "codex" && text)
    }
}
fn content_supported(
    raw: Option<&serde_json::value::RawValue>,
    provider: &'static str,
    deadline: Deadline,
    depth: u32,
) -> bool {
    let Some(raw) = raw else {
        return true;
    };
    if depth > 64 || deadline.check().is_err() {
        return false;
    }
    let mut deserializer = serde_json::Deserializer::from_str(raw.get());
    serde::de::DeserializeSeed::deserialize(
        ContentSeed {
            provider,
            deadline,
            depth,
        },
        &mut deserializer,
    )
    .unwrap_or(false)
}

#[derive(Clone, Copy)]
enum ClaudeMetadataShape {
    Atis,
    Cost,
    Models,
    ModelCounters,
}

struct ClaudeMetadataSeed {
    shape: ClaudeMetadataShape,
    deadline: Deadline,
}

impl<'de> serde::de::DeserializeSeed<'de> for ClaudeMetadataSeed {
    type Value = bool;

    fn deserialize<D: serde::Deserializer<'de>>(self, deserializer: D) -> Result<bool, D::Error> {
        deserializer.deserialize_map(self)
    }
}

impl<'de> serde::de::Visitor<'de> for ClaudeMetadataSeed {
    type Value = bool;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("known Claude runtime metadata")
    }

    fn visit_map<A: serde::de::MapAccess<'de>>(self, mut map: A) -> Result<bool, A::Error> {
        use ClaudeMetadataShape::{Atis, Cost, ModelCounters, Models};
        let fields: &[&str] = match self.shape {
            Atis => &["type", "sessionId", "atis"],
            Cost => &[
                "type",
                "sessionId",
                "totalCostUSD",
                "totalAPIDuration",
                "totalAPIDurationWithoutRetries",
                "totalToolDuration",
                "totalLinesAdded",
                "totalLinesRemoved",
                "totalDuration",
                "startTime",
                "modelUsage",
                "hasUnknownModelCost",
            ],
            Models => &[],
            ModelCounters => &[
                "inputTokens",
                "outputTokens",
                "cacheReadInputTokens",
                "cacheCreationInputTokens",
                "webSearchRequests",
                "costUSD",
                "thinkingTokens",
            ],
        };
        let required = if matches!(self.shape, Cost | ModelCounters) {
            // hasUnknownModelCost and thinkingTokens are optional, but never null.
            fields.len() - 1
        } else {
            fields.len()
        };
        let mut seen = 0_u16;
        loop {
            self.deadline.check().map_err(serde::de::Error::custom)?;
            let Some(key) = map.next_key::<String>()? else {
                break;
            };
            if matches!(self.shape, Models) {
                // Validate one model at a time; never retain the counter map.
                if key.trim().is_empty()
                    || !map.next_value_seed(ClaudeMetadataSeed {
                        shape: ModelCounters,
                        deadline: self.deadline,
                    })?
                {
                    return Ok(false);
                }
                continue;
            }
            let Some(index) = fields.iter().position(|field| *field == key) else {
                return Ok(false);
            };
            let bit = 1 << index;
            if seen & bit != 0 {
                return Ok(false);
            }
            seen |= bit;
            let valid = match key.as_str() {
                "type" => {
                    map.next_value::<String>()?
                        == if matches!(self.shape, Atis) {
                            "atis-latch"
                        } else {
                            "cost-state"
                        }
                }
                "sessionId" => !map.next_value::<String>()?.trim().is_empty(),
                "atis" => {
                    map.next_value::<String>()?;
                    true
                }
                "hasUnknownModelCost" => {
                    map.next_value::<bool>()?;
                    true
                }
                "modelUsage" => map.next_value_seed(ClaudeMetadataSeed {
                    shape: Models,
                    deadline: self.deadline,
                })?,
                _ => {
                    let value = map.next_value::<f64>()?;
                    value.is_finite() && value >= 0.0
                }
            };
            if !valid {
                return Ok(false);
            }
        }
        let required_mask = (1 << required) - 1;
        Ok(seen & required_mask == required_mask)
    }
}

fn claude_metadata_supported(line: &[u8], kind: &str, deadline: Deadline) -> bool {
    let mut deserializer = serde_json::Deserializer::from_slice(line);
    serde::de::DeserializeSeed::deserialize(
        ClaudeMetadataSeed {
            shape: if kind == "atis-latch" {
                ClaudeMetadataShape::Atis
            } else {
                ClaudeMetadataShape::Cost
            },
            deadline,
        },
        &mut deserializer,
    )
    .unwrap_or(false)
        && deserializer.end().is_ok()
}

impl RecordScan {
    fn new(provider: &'static str) -> Self {
        Self {
            provider,
            line: Vec::new(),
            first: true,
            supported: true,
        }
    }
    fn push(&mut self, mut bytes: &[u8], deadline: Deadline) -> io::Result<()> {
        while !bytes.is_empty() {
            deadline.io_check()?;
            let count = bytes
                .iter()
                .position(|&byte| byte == b'\n')
                .map_or(bytes.len(), |index| index + 1);
            let piece = &bytes[..count];
            if self.line.len().saturating_add(piece.len()) as u64 > STREAM_RECORD_MAX_BYTES {
                return Err(io::Error::other(
                    "managed record exceeds the supported bound",
                ));
            }
            self.line
                .try_reserve(piece.len())
                .map_err(|_| io::Error::other("bounded record validation allocation failed"))?;
            self.line.extend_from_slice(piece);
            if piece.last() == Some(&b'\n') {
                self.finish(deadline)?;
            }
            bytes = &bytes[count..];
        }
        Ok(())
    }
    fn finish(&mut self, deadline: Deadline) -> io::Result<()> {
        deadline.io_check()?;
        let line = if self.first {
            self.line
                .strip_prefix(b"\xEF\xBB\xBF")
                .unwrap_or(&self.line)
        } else {
            &self.line
        };
        if !line.iter().all(u8::is_ascii_whitespace) {
            let record = serde_json::from_slice::<RecordDiscriminator>(line);
            deadline.io_check()?;
            self.supported &= record.is_ok_and(|record| {
                let Some(kind) = record.kind.as_deref() else {
                    return false;
                };
                match self.provider {
                    "claude-code" if matches!(kind, "atis-latch" | "cost-state") => {
                        // Last-wins runtime state is not a message or a usage delta.
                        claude_metadata_supported(line, kind, deadline)
                    }
                    "claude-code" => {
                        matches!(
                            kind,
                            "user"
                                | "assistant"
                                | "system"
                                | "summary"
                                | "custom-title"
                                | "mode"
                                | "permission-mode"
                                | "file-history-snapshot"
                                | "file-history-delta"
                                | "attachment"
                                | "last-prompt"
                                | "queue-operation"
                                | "agent-name"
                        ) && record.message.as_deref().is_none_or(|message| {
                            serde_json::from_str::<MessageContent>(message.get()).is_ok_and(
                                |message| {
                                    content_supported(
                                        message.content.as_deref(),
                                        self.provider,
                                        deadline,
                                        0,
                                    )
                                },
                            )
                        })
                    }
                    "codex" if kind == "response_item" => {
                        record.payload.as_deref().is_some_and(|raw| {
                            serde_json::from_str::<PayloadDiscriminator>(raw.get()).is_ok_and(
                                |payload| match payload.kind.as_deref() {
                                    Some("message") => content_supported(
                                        payload.content.as_deref(),
                                        self.provider,
                                        deadline,
                                        0,
                                    ),
                                    Some(
                                        "reasoning"
                                        | "function_call"
                                        | "function_call_output"
                                        | "custom_tool_call"
                                        | "custom_tool_call_output",
                                    ) => true,
                                    _ => false,
                                },
                            )
                        })
                    }
                    "codex" => matches!(
                        kind,
                        "session_meta"
                            | "event_msg"
                            | "turn_context"
                            | "world_state"
                            | "compacted"
                            | "token_usage_record"
                    ),
                    "workbuddy" => match kind {
                        "message" => {
                            content_supported(record.content.as_deref(), self.provider, deadline, 0)
                        }
                        "session-meta"
                        | "ai-title"
                        | "reasoning"
                        | "function_call"
                        | "function_call_result"
                        | "file-history-snapshot" => true,
                        _ => false,
                    },
                    _ => false,
                }
            });
        }
        self.first = false;
        self.line.clear();
        Ok(())
    }
}

struct DeadlineSink<'a> {
    inner: &'a mut dyn CanonicalEventSink,
    deadline: Deadline,
}
impl CanonicalEventSink for DeadlineSink<'_> {
    fn emit_message(&mut self, event: MessageEvent<'_>) -> PortResult<()> {
        self.deadline.port_check()?;
        let result = self.inner.emit_message(event);
        self.deadline.port_check()?;
        result.map_err(|_| PortError::SourceIo("managed message staging failed".into()))
    }
    fn emit_activity(&mut self, event: ToolActivityEvent<'_>) -> PortResult<()> {
        self.deadline.port_check()?;
        let result = self.inner.emit_activity(event);
        self.deadline.port_check()?;
        result.map_err(|_| PortError::SourceIo("managed activity staging failed".into()))
    }
    fn emit_usage(&mut self, event: UsageEvent<'_>) -> PortResult<()> {
        self.deadline.port_check()?;
        let result = self.inner.emit_usage(event);
        self.deadline.port_check()?;
        result.map_err(|_| PortError::SourceIo("managed usage staging failed".into()))
    }
}
struct DeadlineAdapter<'a> {
    inner: &'a dyn ProviderAdapter,
    source: &'a DeadlineSource<'a>,
    deadline: Deadline,
}
impl ProviderAdapter for DeadlineAdapter<'_> {
    fn provider_id(&self) -> &str {
        self.inner.provider_id()
    }
    fn manifest(&self) -> AdapterManifest {
        self.inner.manifest()
    }
    fn probe(&self, bytes: &[u8]) -> Result<ProbeResult, ProviderError> {
        self.deadline.check()?;
        let result = self.inner.probe(bytes);
        self.deadline.check()?;
        result.map_err(redact_provider)
    }
    fn parse(
        &self,
        bytes: &[u8],
        sink: &mut dyn CanonicalEventSink,
    ) -> Result<ParseReport, ProviderError> {
        self.deadline.check()?;
        let result = self.inner.parse(
            bytes,
            &mut DeadlineSink {
                inner: sink,
                deadline: self.deadline,
            },
        );
        self.deadline.check()?;
        result.map_err(redact_provider)
    }
    fn probe_source(&self, source: &dyn ReadOnlySource) -> Result<ProbeResult, ProviderError> {
        self.deadline.check()?;
        let result = self.inner.probe_source(source);
        if let Ok(probe) = &result {
            self.source.strong_format.store(
                matches!(
                    probe.confidence,
                    agent_session_grep_ports::Confidence::High
                        | agent_session_grep_ports::Confidence::Confirmed
                ),
                Ordering::Relaxed,
            );
        }
        self.deadline.check()?;
        result.map_err(redact_provider)
    }
    fn parse_source(
        &self,
        source: &dyn ReadOnlySource,
        sink: &mut dyn CanonicalEventSink,
    ) -> Result<ParseReport, ProviderError> {
        self.deadline.check()?;
        self.source.reset_parse_scan();
        let result = self.inner.parse_source(
            source,
            &mut DeadlineSink {
                inner: sink,
                deadline: self.deadline,
            },
        );
        self.deadline.check()?;
        result.map_err(redact_provider)
    }
}

#[cfg(test)]
#[path = "managed_source_parse_tests.rs"]
mod tests;
