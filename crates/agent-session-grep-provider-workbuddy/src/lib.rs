//! WorkBuddy project JSONL, independently identified from Tencent CodeBuddy CLI.
//!
//! Implements the structural record contract in the active Beta task's corrected
//! four-host evidence. All tests are synthesized; no upstream implementation or
//! private transcript is copied. The parser consumes captured bytes only.
//!
//! This file format cannot prove a session is active: WorkBuddy retains local
//! JSONL after soft deletion. Call inspect_session_state with an independently
//! captured logical SQLite snapshot before making lifecycle claims. Acquisition
//! of a coherent DB/WAL snapshot remains the composition layer's responsibility.

use agent_session_grep_domain::{ToolActivityActor, ToolActivityStatus};
use agent_session_grep_ports::{
    AdapterManifest, BoundedLineReader, CanonicalEventSink, Confidence, MessageEvent,
    MetadataResolution, ParseReport, ProbeResult, ProviderAdapter, ProviderError, ReadOnlySource,
    STREAM_RECORD_MAX_BYTES, SliceSource, ToolActivityEvent, build_tool_activity, manifest_for,
};
use rusqlite::{Connection, MAIN_DB, types::ValueRef};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    io::Read,
    time::{Duration, Instant},
};

pub const PROVIDER_ID: &str = "workbuddy";
pub const VARIANT_ID: &str = "workbuddy/project-jsonl-v1";
const SAMPLE_LINES: usize = 8;
const MAX_DIAGNOSTICS: usize = 32;
const MAX_PENDING_CALLS: usize = 256;
const MIN_EPOCH_MS: i64 = -62_167_219_200_000;
const MAX_EPOCH_MS: i64 = 253_402_300_799_999;

#[derive(Debug, Default, Clone, Copy)]
pub struct WorkBuddyAdapter;
impl WorkBuddyAdapter {
    pub fn new() -> Self {
        Self
    }
}

fn note(report: &mut ParseReport, line: usize, reason: &str) {
    if report.diagnostics.len() < MAX_DIAGNOSTICS {
        report.diagnostics.push(format!("line {line}: {reason}"));
    }
}
fn skip(report: &mut ParseReport, line: usize, reason: &str) {
    report.skipped += 1;
    note(report, line, reason);
}
fn nonblank(value: &Value) -> Option<&str> {
    value.as_str().filter(|value| !value.trim().is_empty())
}
fn metadata_kind(kind: &str) -> bool {
    matches!(
        kind,
        "session-meta"
            | "ai-title"
            | "reasoning"
            | "function_call"
            | "function_call_result"
            | "file-history-snapshot"
    )
}
fn local_marker(row: &Value) -> bool {
    row.get("__codebuddyLocal").is_some_and(Value::is_object)
}
fn host_kind(row: &Value) -> Option<&str> {
    row.get("meta")
        .and_then(|meta| meta.get("codebuddy.ai/hostKind"))
        .and_then(nonblank)
}
fn cli_host_kind(kind: &str) -> bool {
    matches!(kind, "cli" | "codebuddy-cli" | "tencent-codebuddy")
}
fn optional_identity_matches(row: &Value, field: &str, expected: Option<&str>) -> bool {
    match row.get(field) {
        None | Some(Value::Null) => true,
        Some(value) => nonblank(value).is_some_and(|observed| Some(observed) == expected),
    }
}
fn message_shape(row: &Value) -> bool {
    row.get("type").and_then(Value::as_str) == Some("message")
        && row
            .get("role")
            .and_then(Value::as_str)
            .is_some_and(valid_role)
        && row.get("message").is_none()
        && row.get("sessionId").and_then(nonblank).is_some()
        && row.get("timestamp").and_then(Value::as_i64).is_some()
        && row
            .get("content")
            .and_then(Value::as_array)
            .is_some_and(|blocks| {
                blocks.iter().any(|block| {
                    block.get("type").and_then(Value::as_str) == Some("text")
                        && block.get("text").is_some_and(Value::is_string)
                })
            })
}
fn valid_role(role: &str) -> bool {
    matches!(role, "user" | "assistant" | "system" | "developer" | "tool")
}
fn ambiguous() -> ProviderError {
    ProviderError::AmbiguousVariant("no unique WorkBuddy project JSONL evidence".into())
}

impl ProviderAdapter for WorkBuddyAdapter {
    fn provider_id(&self) -> &str {
        PROVIDER_ID
    }
    fn manifest(&self) -> AdapterManifest {
        // Main registers the independent capability row. No private fallback
        // matrix and no borrowing of Tencent CodeBuddy's identity or maturity.
        manifest_for(
            PROVIDER_ID,
            Some(2),
            &[
                "JSONL presence does not establish active or nondeleted session state",
                "soft-delete inspection requires an already-logical WorkBuddy SQLite snapshot",
                "cloud sessions have no proven local history surface",
                "merged files retain first-session membership and report ambiguous resume metadata",
                "reasoning, titles, file snapshots and unanchored tool records are not conversation",
                "usage buckets and branch parentage have no verified mapping in this variant",
            ],
        )
    }
    fn probe(&self, bytes: &[u8]) -> Result<ProbeResult, ProviderError> {
        let source = SliceSource::new(bytes);
        let mut lines = BoundedLineReader::new(&source, STREAM_RECORD_MAX_BYTES)
            .map_err(|_| ProviderError::Io("WorkBuddy probe source unavailable".into()))?;
        let mut sampled = 0;
        let mut header = false;
        let mut message = false;
        let mut marked_message = false;
        let mut conflicting = false;
        let mut unmatched = Vec::new();
        while sampled < SAMPLE_LINES {
            let Some(line) = lines.next_record()? else {
                break;
            };
            if line.bytes.iter().all(u8::is_ascii_whitespace) {
                continue;
            }
            sampled += 1;
            let Ok(row) = serde_json::from_slice::<Value>(line.bytes) else {
                unmatched.push(format!("line {}: invalid JSON record", line.number));
                continue;
            };
            conflicting |= host_kind(&row).is_some_and(cli_host_kind);
            match row.get("type").and_then(Value::as_str) {
                Some("session-meta") => {
                    header |= host_kind(&row).is_some_and(|kind| !cli_host_kind(kind))
                        && row.get("sessionId").and_then(nonblank).is_some()
                        && row.get("timestamp").and_then(Value::as_i64).is_some();
                }
                Some("message") if message_shape(&row) => {
                    message = true;
                    marked_message |= local_marker(&row);
                }
                Some(kind) if metadata_kind(kind) => {}
                Some(
                    "user"
                    | "assistant"
                    | "session"
                    | "context.append_message"
                    | "response_item"
                    | "session_meta",
                ) => {
                    conflicting = true;
                }
                _ => {
                    unmatched.push(format!(
                        "line {}: incompatible conversation shape",
                        line.number
                    ));
                }
            }
        }
        let confidence = if conflicting {
            Confidence::Ambiguous
        } else if header && message {
            Confidence::Confirmed
        } else if header || marked_message {
            Confidence::High
        } else if message {
            Confidence::Low
        } else {
            Confidence::Ambiguous
        };
        let mut matched = Vec::new();
        if header {
            matched.push(
                "session-meta hostKind marker with native sessionId and epoch-ms timestamp".into(),
            );
        }
        if message {
            matched.push(
                "top-level message role and ordered text parts with integer epoch-ms timestamp"
                    .into(),
            );
        }
        if marked_message {
            matched.push("message __codebuddyLocal object marker".into());
        }
        if conflicting {
            unmatched.push("another provider's record vocabulary is present".into());
        }
        Ok(ProbeResult {
            variant_id: VARIANT_ID.into(),
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
        self.parse_source(&SliceSource::new(bytes), sink)
    }
    fn parse_source(
        &self,
        source: &dyn ReadOnlySource,
        sink: &mut dyn CanonicalEventSink,
    ) -> Result<ParseReport, ProviderError> {
        let sample = probe_prefix(source)?;
        if !matches!(
            self.probe(&sample)?.confidence,
            Confidence::High | Confidence::Confirmed
        ) {
            return Err(ambiguous());
        }
        let mut lines = BoundedLineReader::new(source, STREAM_RECORD_MAX_BYTES)
            .map_err(|_| ProviderError::Io("WorkBuddy source unavailable".into()))?;
        let mut report = ParseReport::default();
        let mut seq = 0_u32;
        let mut current_session: Option<String> = None;
        let mut anchor: Option<String> = None;
        let mut calls: BTreeMap<String, PendingCall> = BTreeMap::new();
        let mut duplicate_calls = BTreeSet::new();
        let mut pending_bytes = 0_u64;
        while let Some(line) = lines.next_record()? {
            if line.bytes.iter().all(u8::is_ascii_whitespace) {
                continue;
            }
            let row: Value = match serde_json::from_slice(line.bytes) {
                Ok(row) => row,
                Err(_) => {
                    invalidate_anchor(sink, &mut calls, &mut anchor)?;
                    duplicate_calls.clear();
                    pending_bytes = 0;
                    skip(
                        &mut report,
                        line.number,
                        "invalid or torn JSON record, skipped",
                    );
                    continue;
                }
            };
            let kind = row.get("type").and_then(Value::as_str).unwrap_or("");
            match kind {
                "session-meta" => {
                    let session = row.get("sessionId").and_then(nonblank);
                    if session.is_some_and(|id| current_session.as_deref() != Some(id)) {
                        flush_calls(sink, &mut calls)?;
                        anchor = None;
                        duplicate_calls.clear();
                        pending_bytes = 0;
                    }
                    if let Some(session) = session {
                        current_session = Some(session.into());
                    }
                    observe_session(&mut report, &row);
                }
                "message" => {
                    let Some(role) = row
                        .get("role")
                        .and_then(Value::as_str)
                        .filter(|role| valid_role(role))
                    else {
                        invalidate_anchor(sink, &mut calls, &mut anchor)?;
                        duplicate_calls.clear();
                        pending_bytes = 0;
                        skip(
                            &mut report,
                            line.number,
                            "missing or unknown message role, skipped",
                        );
                        continue;
                    };
                    let text = match message_text(&row) {
                        Some(text) => text,
                        None => {
                            invalidate_anchor(sink, &mut calls, &mut anchor)?;
                            duplicate_calls.clear();
                            pending_bytes = 0;
                            skip(
                                &mut report,
                                line.number,
                                "missing or malformed message text parts, skipped",
                            );
                            continue;
                        }
                    };
                    let native = match row.get("id") {
                        None | Some(Value::Null) => "",
                        Some(Value::String(value)) => {
                            if value.trim().is_empty() {
                                ""
                            } else {
                                value
                            }
                        }
                        _ => {
                            invalidate_anchor(sink, &mut calls, &mut anchor)?;
                            duplicate_calls.clear();
                            pending_bytes = 0;
                            skip(
                                &mut report,
                                line.number,
                                "invalid message identity type, skipped",
                            );
                            continue;
                        }
                    };
                    let timestamp = match row.get("timestamp") {
                        None | Some(Value::Null) => None,
                        Some(value) => match value.as_i64().and_then(epoch_ms_utc) {
                            Some(value) => Some(value),
                            None => {
                                invalidate_anchor(sink, &mut calls, &mut anchor)?;
                                duplicate_calls.clear();
                                pending_bytes = 0;
                                skip(
                                    &mut report,
                                    line.number,
                                    "invalid or out-of-range epoch-ms timestamp, skipped",
                                );
                                continue;
                            }
                        },
                    };
                    if row
                        .get("sessionId")
                        .is_some_and(|value| !value.is_null() && !value.is_string())
                        || row
                            .get("cwd")
                            .is_some_and(|value| !value.is_null() && !value.is_string())
                    {
                        invalidate_anchor(sink, &mut calls, &mut anchor)?;
                        duplicate_calls.clear();
                        pending_bytes = 0;
                        skip(
                            &mut report,
                            line.number,
                            "invalid session metadata type, skipped",
                        );
                        continue;
                    }
                    let session = row.get("sessionId").and_then(nonblank);
                    if let Some(session) = session {
                        current_session = Some(session.into());
                    }
                    observe_session(&mut report, &row);
                    flush_calls(sink, &mut calls)?;
                    duplicate_calls.clear();
                    pending_bytes = 0;
                    anchor = (role == "assistant" && !native.trim().is_empty())
                        .then(|| native.to_string());
                    sink.emit_message(MessageEvent {
                        session: None,
                        seq,
                        native_id: native,
                        parent_native_id: None,
                        role,
                        text: &text,
                        timestamp: timestamp.as_deref(),
                        is_sidechain: false,
                        span: Some((line.start, line.end)),
                    })
                    .map_err(|_| ProviderError::Io("WorkBuddy message sink unavailable".into()))?;
                    seq = seq.checked_add(1).ok_or_else(|| {
                        ProviderError::StructuralFatal("WorkBuddy message ordinal overflow".into())
                    })?;
                    report.committed += 1;
                }
                "function_call" => {
                    let same_session =
                        optional_identity_matches(&row, "sessionId", current_session.as_deref());
                    let same_anchor = row
                        .get("messageId")
                        .and_then(nonblank)
                        .is_some_and(|message| anchor.as_deref() == Some(message));
                    let (Some(caller), Some(call_id), Some(name)) = (
                        anchor.as_deref().filter(|_| same_session && same_anchor),
                        row.get("callId").and_then(nonblank),
                        row.get("name").and_then(nonblank),
                    ) else {
                        note(
                            &mut report,
                            line.number,
                            "tool call has no verified current message/call anchor, ignored",
                        );
                        continue;
                    };
                    if duplicate_calls.contains(call_id) || calls.remove(call_id).is_some() {
                        duplicate_calls.insert(call_id.to_string());
                        note(
                            &mut report,
                            line.number,
                            "duplicate pending tool call identity, ignored",
                        );
                        continue;
                    }
                    pending_bytes = pending_bytes
                        .saturating_add(line.bytes.len() as u64)
                        .saturating_add(caller.len() as u64);
                    if calls.len() + duplicate_calls.len() >= MAX_PENDING_CALLS
                        || pending_bytes > STREAM_RECORD_MAX_BYTES
                    {
                        return Err(ProviderError::StructuralFatal(
                            "WorkBuddy pending tool-call budget exceeded".into(),
                        ));
                    }
                    let input = match row.get("arguments") {
                        Some(Value::String(raw)) => {
                            serde_json::from_str(raw).unwrap_or(Value::Null)
                        }
                        Some(value) => value.clone(),
                        None => Value::Null,
                    };
                    calls.insert(
                        call_id.into(),
                        PendingCall {
                            caller: caller.into(),
                            name: name.into(),
                            input,
                        },
                    );
                }
                "function_call_result" => {
                    let Some(call_id) = row.get("callId").and_then(nonblank) else {
                        continue;
                    };
                    if duplicate_calls.contains(call_id) {
                        continue;
                    }
                    let Some(call) = calls.remove(call_id) else {
                        note(&mut report, line.number, "unpaired tool result, ignored");
                        continue;
                    };
                    let same_session =
                        optional_identity_matches(&row, "sessionId", current_session.as_deref());
                    let same_anchor =
                        optional_identity_matches(&row, "messageId", Some(call.caller.as_str()));
                    let status = if same_session && same_anchor {
                        match row.get("status").and_then(Value::as_str) {
                            Some("success") => ToolActivityStatus::Success,
                            Some("error" | "failed") => ToolActivityStatus::Error,
                            _ => ToolActivityStatus::Unknown,
                        }
                    } else {
                        ToolActivityStatus::Unknown
                    };
                    emit_call(sink, &call, status)?;
                }
                "ai-title" | "reasoning" | "file-history-snapshot" => {}
                _ => {
                    invalidate_anchor(sink, &mut calls, &mut anchor)?;
                    duplicate_calls.clear();
                    pending_bytes = 0;
                    skip(
                        &mut report,
                        line.number,
                        "unknown record discriminator, skipped",
                    );
                }
            }
        }
        flush_calls(sink, &mut calls)?;
        if report.session_observation.multi_session {
            note(
                &mut report,
                0,
                "multiple sessionIds: first-session membership retained; resume metadata ambiguous",
            );
        }
        Ok(report)
    }
}

fn probe_prefix(source: &dyn ReadOnlySource) -> Result<Vec<u8>, ProviderError> {
    let mut lines = BoundedLineReader::new(source, STREAM_RECORD_MAX_BYTES)
        .map_err(|_| ProviderError::Io("WorkBuddy probe source unavailable".into()))?;
    let mut prefix = Vec::new();
    let mut records = 0;
    while records < SAMPLE_LINES {
        let Some(line) = lines.next_record()? else {
            break;
        };
        if line.bytes.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        if prefix
            .len()
            .saturating_add(line.bytes.len())
            .saturating_add(1)
            > STREAM_RECORD_MAX_BYTES as usize
        {
            break;
        }
        prefix.extend_from_slice(line.bytes);
        prefix.push(b'\n');
        records += 1;
    }
    Ok(prefix)
}

fn message_text(row: &Value) -> Option<String> {
    let blocks = row.get("content")?.as_array()?;
    let mut parts = Vec::new();
    for block in blocks {
        let kind = block.get("type")?.as_str()?;
        if kind == "text" {
            parts.push(block.get("text")?.as_str()?);
        }
    }
    (!parts.is_empty()).then(|| parts.join("\n"))
}
fn observe_session(report: &mut ParseReport, row: &Value) {
    let Some(session) = row.get("sessionId").and_then(nonblank) else {
        return;
    };
    if report.session_native_id.is_none() {
        report.session_native_id = Some(session.into());
        report.session_observation.provider_session_id =
            MetadataResolution::Resolved(session.into());
    } else if report.session_native_id.as_deref() != Some(session) {
        report.session_observation.multi_session = true;
        report.session_observation.provider_session_id = MetadataResolution::Ambiguous;
        report.session_observation.original_working_directory = MetadataResolution::Ambiguous;
    }
    if report.session_observation.multi_session {
        return;
    }
    if let Some(cwd) = row.get("cwd").and_then(nonblank) {
        match &report.session_observation.original_working_directory {
            MetadataResolution::Missing => {
                report.session_observation.original_working_directory =
                    MetadataResolution::Resolved(cwd.into());
            }
            MetadataResolution::Resolved(previous) if previous != cwd => {
                report.session_observation.original_working_directory =
                    MetadataResolution::Ambiguous;
            }
            _ => {}
        }
        report.session_observation.pair_observed = true;
    }
}
struct PendingCall {
    caller: String,
    name: String,
    input: Value,
}
fn emit_call(
    sink: &mut dyn CanonicalEventSink,
    call: &PendingCall,
    status: ToolActivityStatus,
) -> Result<(), ProviderError> {
    sink.emit_activity(ToolActivityEvent {
        message_native_id: &call.caller,
        activity: build_tool_activity(&call.name, ToolActivityActor::Main, &call.input, status),
    })
    .map_err(|_| ProviderError::Io("WorkBuddy tool sink unavailable".into()))
}
fn invalidate_anchor(
    sink: &mut dyn CanonicalEventSink,
    calls: &mut BTreeMap<String, PendingCall>,
    anchor: &mut Option<String>,
) -> Result<(), ProviderError> {
    flush_calls(sink, calls)?;
    *anchor = None;
    Ok(())
}
fn flush_calls(
    sink: &mut dyn CanonicalEventSink,
    calls: &mut BTreeMap<String, PendingCall>,
) -> Result<(), ProviderError> {
    for (_, call) in std::mem::take(calls) {
        emit_call(sink, &call, ToolActivityStatus::Unknown)?;
    }
    Ok(())
}

/// Gregorian conversion at millisecond precision, bounded to four-digit UTC
/// years. Euclidean division preserves negative instants without rounding.
fn epoch_ms_utc(ms: i64) -> Option<String> {
    if !(MIN_EPOCH_MS..=MAX_EPOCH_MS).contains(&ms) {
        return None;
    }
    let days = ms.div_euclid(86_400_000);
    let time = ms.rem_euclid(86_400_000);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let day_of_era = z - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36524 - day_of_era / 146096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    if month <= 2 {
        year += 1;
    }
    Some(format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{:03}Z",
        time / 3_600_000,
        (time % 3_600_000) / 60_000,
        (time % 60_000) / 1000,
        time % 1000
    ))
}

/// Availability is independent of whether a JSONL file currently exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionDeletionState {
    ActiveLocal,
    SoftDeleted,
    CloudUnavailable,
    OrphanUnknown,
}
#[derive(Clone, PartialEq, Eq)]
pub struct SessionState {
    pub state: SessionDeletionState,
    /// Private provider-recorded working directory; never a guessed project ID.
    pub cwd: Option<String>,
}
impl fmt::Debug for SessionState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionState")
            .field("state", &self.state)
            .field("cwd_present", &self.cwd.is_some())
            .finish()
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionStateError {
    InvalidRequest,
    SnapshotTooLarge,
    /// The complete metadata batch exceeds its row or returned-content bound.
    InspectionTooLarge,
    Deadline,
    Unreadable,
    UnsupportedSchema,
    AmbiguousSession,
}
impl fmt::Display for SessionStateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "WorkBuddy session-state inspection: {self:?}")
    }
}
impl std::error::Error for SessionStateError {}
fn state_deadline(deadline: Instant) -> Result<(), SessionStateError> {
    if Instant::now() >= deadline {
        Err(SessionStateError::Deadline)
    } else {
        Ok(())
    }
}
fn state_sql(error: rusqlite::Error, deadline: Instant) -> SessionStateError {
    if Instant::now() >= deadline
        || matches!(
            error.sqlite_error_code(),
            Some(rusqlite::ErrorCode::OperationInterrupted)
        )
    {
        SessionStateError::Deadline
    } else {
        SessionStateError::Unreadable
    }
}

// Bounds apply to metadata only; no message body or provider content is read.
const MAX_STATE_ROWS: usize = 65_536;
const MAX_STATE_CONTENT_BYTES: usize = 32 * 1024 * 1024;
const MAX_STATE_CWD_BYTES: usize = 65_536;
const STATE_COPY_CHUNK_BYTES: usize = 65_536;

/// Copy the image in finite chunks under the original caller deadline. The
/// destination is SQLite's single owned deserialize allocation, never a live DB.
struct StateImageReader<R> {
    inner: R,
    deadline: Instant,
}
impl<R: Read> Read for StateImageReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        if Instant::now() >= self.deadline {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "WorkBuddy snapshot copy deadline expired",
            ));
        }
        let length = buffer.len().min(STATE_COPY_CHUNK_BYTES);
        let copied = self.inner.read(&mut buffer[..length])?;
        if Instant::now() >= self.deadline {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "WorkBuddy snapshot copy deadline expired",
            ));
        }
        Ok(copied)
    }
}

fn open_state_snapshot(
    snapshot: &[u8],
    deadline: Instant,
) -> Result<Connection, SessionStateError> {
    state_deadline(deadline)?;
    if snapshot.len() as u64 > agent_session_grep_ports::SQLITE_MAX_SOURCE_BYTES {
        return Err(SessionStateError::SnapshotTooLarge);
    }
    if snapshot.len() < 100 || !snapshot.starts_with(b"SQLite format 3\0") {
        return Err(SessionStateError::Unreadable);
    }
    // The caller guarantees a coherent logical image. SQLite's Online Backup
    // API can preserve WAL format markers (2/2); those markers do not prove or
    // disprove snapshot coherence. Reject invalid/mixed versions and normalize
    // only the private deserialize allocation. The caller's bytes never change.
    if !matches!((snapshot[18], snapshot[19]), (1, 1) | (2, 2)) {
        return Err(SessionStateError::Unreadable);
    }
    let mut conn = Connection::open_in_memory().map_err(|error| state_sql(error, deadline))?;
    let image = (&snapshot[..18])
        .chain(&[1_u8, 1][..])
        .chain(&snapshot[20..]);
    conn.deserialize_read_exact(
        MAIN_DB,
        StateImageReader {
            inner: image,
            deadline,
        },
        snapshot.len(),
        true,
    )
    .map_err(|error| state_sql(error, deadline))?;
    state_deadline(deadline)?;
    conn.busy_timeout(
        deadline
            .saturating_duration_since(Instant::now())
            .min(Duration::from_millis(50)),
    )
    .map_err(|error| state_sql(error, deadline))?;
    conn.progress_handler(1000, Some(move || Instant::now() >= deadline))
        .map_err(|error| state_sql(error, deadline))?;
    conn.execute_batch("PRAGMA query_only=ON; PRAGMA trusted_schema=OFF;")
        .map_err(|error| state_sql(error, deadline))?;
    let schema_ok: bool = conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name='sessions' AND type='table')",
            [],
            |row| row.get(0),
        )
        .map_err(|error| state_sql(error, deadline))?;
    if !schema_ok {
        return Err(SessionStateError::UnsupportedSchema);
    }
    let mut required = [false; 4];
    let mut schema = conn
        .prepare("PRAGMA table_info(sessions)")
        .map_err(|error| state_sql(error, deadline))?;
    let mut columns = schema
        .query([])
        .map_err(|error| state_sql(error, deadline))?;
    while let Some(column) = columns.next().map_err(|error| state_sql(error, deadline))? {
        state_deadline(deadline)?;
        let ValueRef::Text(name) = column
            .get_ref(1)
            .map_err(|error| state_sql(error, deadline))?
        else {
            return Err(SessionStateError::UnsupportedSchema);
        };
        for (index, expected) in [b"id".as_slice(), b"deleted_at", b"transport", b"cwd"]
            .iter()
            .enumerate()
        {
            if name == *expected {
                required[index] = true;
            }
        }
    }
    if required.iter().any(|present| !present) {
        return Err(SessionStateError::UnsupportedSchema);
    }
    state_deadline(deadline)?;
    drop(columns);
    drop(schema);
    Ok(conn)
}

// Both APIs use exactly this field decoder. Unknown transport strings remain
// OrphanUnknown; malformed stored types never imply deletion or an empty batch.
fn decode_session_state(
    row: &rusqlite::Row<'_>,
    first: usize,
    deadline: Instant,
) -> Result<SessionState, SessionStateError> {
    state_deadline(deadline)?;
    let deleted = match row
        .get_ref(first)
        .map_err(|error| state_sql(error, deadline))?
    {
        ValueRef::Null => false,
        ValueRef::Integer(value) if value >= 0 => true,
        _ => return Err(SessionStateError::UnsupportedSchema),
    };
    let transport = match row
        .get_ref(first + 1)
        .map_err(|error| state_sql(error, deadline))?
    {
        ValueRef::Null => None,
        ValueRef::Text(value) => {
            Some(std::str::from_utf8(value).map_err(|_| SessionStateError::UnsupportedSchema)?)
        }
        _ => return Err(SessionStateError::UnsupportedSchema),
    };
    let state = if deleted {
        SessionDeletionState::SoftDeleted
    } else {
        match transport {
            Some("local") => SessionDeletionState::ActiveLocal,
            Some("cloud") => SessionDeletionState::CloudUnavailable,
            _ => SessionDeletionState::OrphanUnknown,
        }
    };
    let cwd_bytes: i64 = row
        .get(first + 3)
        .map_err(|error| state_sql(error, deadline))?;
    if cwd_bytes < 0 || cwd_bytes as usize > MAX_STATE_CWD_BYTES {
        return Err(SessionStateError::UnsupportedSchema);
    }
    let cwd = match row
        .get_ref(first + 2)
        .map_err(|error| state_sql(error, deadline))?
    {
        ValueRef::Null => None,
        ValueRef::Text(value) => {
            let value =
                std::str::from_utf8(value).map_err(|_| SessionStateError::UnsupportedSchema)?;
            (!value.trim().is_empty()).then(|| value.to_string())
        }
        _ => return Err(SessionStateError::UnsupportedSchema),
    };
    state_deadline(deadline)?;
    Ok(SessionState { state, cwd })
}

/// Inspect only an already-coherent logical SQLite image. No live database,
/// path, WAL file, profile or provider history is opened or modified. Missing
/// sessions rows yield OrphanUnknown; read/schema failure is an error, never a
/// deletion signal. The caller retains ownership of all input bytes.
pub fn inspect_session_state(
    snapshot: &[u8],
    session_id: &str,
    deadline: Instant,
) -> Result<SessionState, SessionStateError> {
    state_deadline(deadline)?;
    if session_id.trim().is_empty() || session_id.len() as u64 > STREAM_RECORD_MAX_BYTES {
        return Err(SessionStateError::InvalidRequest);
    }
    let conn = open_state_snapshot(snapshot, deadline)?;
    // Native IDs are exact text, regardless of a provider column's collation
    // or numeric affinity. Unary + removes affinity; BINARY preserves bytes.
    let mut stmt = conn
        .prepare("SELECT deleted_at,transport,CASE WHEN length(CAST(cwd AS BLOB))<=?2 THEN cwd ELSE NULL END,COALESCE(length(CAST(cwd AS BLOB)),0) FROM sessions WHERE typeof(id)='text' AND +id COLLATE BINARY=?1 LIMIT 2")
        .map_err(|error| state_sql(error, deadline))?;
    let mut rows = stmt
        .query(rusqlite::params![session_id, MAX_STATE_CWD_BYTES as i64])
        .map_err(|error| state_sql(error, deadline))?;
    let Some(row) = rows.next().map_err(|error| state_sql(error, deadline))? else {
        state_deadline(deadline)?;
        return Ok(SessionState {
            state: SessionDeletionState::OrphanUnknown,
            cwd: None,
        });
    };
    let state = decode_session_state(row, 0, deadline)?;
    if rows
        .next()
        .map_err(|error| state_sql(error, deadline))?
        .is_some()
    {
        return Err(SessionStateError::AmbiguousSession);
    }
    state_deadline(deadline)?;
    Ok(state)
}

/// Inspect every sessions row in one already-coherent logical SQLite image,
/// deserializing it once. The returned batch contains only exact native IDs and
/// observed availability/cwd, sorted by native ID bytes. An empty valid table
/// yields an empty batch; an ID absent from the batch remains OrphanUnknown for
/// the caller and must not become deletion evidence.
///
/// At most 65,536 rows and 32 MiB of returned ID/cwd bytes are admitted; native
/// IDs retain all their bytes up to the existing 8 MiB record bound, cwd up to
/// 64 KiB. Duplicates, malformed fields, read errors, limit or deadline expiry
/// reject the entire batch, with no partial authoritative deletion result.
/// Future/null transport strings are OrphanUnknown, not schema failure.
/// No source path, provider message content, cloud or live WAL is opened.
pub fn inspect_session_states(
    snapshot: &[u8],
    deadline: Instant,
) -> Result<Vec<(String, SessionState)>, SessionStateError> {
    let conn = open_state_snapshot(snapshot, deadline)?;
    let mut stmt = conn
        .prepare("SELECT CASE WHEN length(CAST(id AS BLOB))<=?1 THEN id ELSE NULL END,COALESCE(length(CAST(id AS BLOB)),0),deleted_at,transport,CASE WHEN length(CAST(cwd AS BLOB))<=?2 THEN cwd ELSE NULL END,COALESCE(length(CAST(cwd AS BLOB)),0) FROM sessions LIMIT ?3")
        .map_err(|error| state_sql(error, deadline))?;
    let mut rows = stmt
        .query(rusqlite::params![
            STREAM_RECORD_MAX_BYTES as i64,
            MAX_STATE_CWD_BYTES as i64,
            (MAX_STATE_ROWS + 1) as i64,
        ])
        .map_err(|error| state_sql(error, deadline))?;
    let mut states = BTreeMap::new();
    let mut content_bytes = 0_usize;
    while let Some(row) = rows.next().map_err(|error| state_sql(error, deadline))? {
        state_deadline(deadline)?;
        if states.len() == MAX_STATE_ROWS {
            return Err(SessionStateError::InspectionTooLarge);
        }
        let id_bytes: i64 = row.get(1).map_err(|error| state_sql(error, deadline))?;
        if id_bytes < 0 || id_bytes as u64 > STREAM_RECORD_MAX_BYTES {
            return Err(SessionStateError::InspectionTooLarge);
        }
        let ValueRef::Text(id) = row.get_ref(0).map_err(|error| state_sql(error, deadline))? else {
            return Err(SessionStateError::UnsupportedSchema);
        };
        let id = std::str::from_utf8(id).map_err(|_| SessionStateError::UnsupportedSchema)?;
        if id.trim().is_empty() {
            return Err(SessionStateError::UnsupportedSchema);
        }
        if states.contains_key(id) {
            return Err(SessionStateError::AmbiguousSession);
        }
        let state = decode_session_state(row, 2, deadline)?;
        content_bytes = content_bytes
            .checked_add(id.len())
            .and_then(|sum| sum.checked_add(state.cwd.as_ref().map_or(0, String::len)))
            .filter(|sum| *sum <= MAX_STATE_CONTENT_BYTES)
            .ok_or(SessionStateError::InspectionTooLarge)?;
        states.insert(id.to_owned(), state);
    }
    state_deadline(deadline)?;
    let batch = states.into_iter().collect();
    state_deadline(deadline)?;
    Ok(batch)
}
