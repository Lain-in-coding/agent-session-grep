//! Independent ZCode provider for a caller-owned logical SQLite snapshot.
//!
//! The caller acquires a standalone image through SQLite's logical backup API,
//! including committed WAL content. This crate never opens a source path,
//! writes a temporary database, or changes the input image. Its contract is the
//! session/message/part graph with sequence columns and a session_entry table.
//! Session version strings and SQLite user_version are not format gates.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io::Read;
use std::time::{Duration, Instant};

use agent_session_grep_domain::{IdKind, StableId, ToolActivityActor, ToolActivityStatus};
use agent_session_grep_ports::{
    AdapterManifest, CanonicalEventSink, Confidence, MessageEvent, MetadataResolution, ParseReport,
    ProbeResult, ProviderAdapter, ProviderError, ProviderSessionIdentity,
    ProviderSessionObservation, ReadOnlySource, STREAM_RECORD_MAX_BYTES, ToolActivityEvent,
    build_tool_activity, manifest_for, read_bounded_source,
};
use rusqlite::{Connection, MAIN_DB, Row, types::ValueRef};
use serde::Deserialize;
use serde_json::{Value, value::RawValue};

pub const PROVIDER_ID: &str = "zcode";
pub const VARIANT_ID: &str = "zcode/sqlite-v1";
/// Explicit whole-image limit; decoded graph allocations keep their separate 128 MiB cap.
pub const MAX_SQLITE_BYTES: u64 = agent_session_grep_ports::manifest::ZCODE_MAX_SOURCE_BYTES;
const DEFAULT_BUDGET: Duration = Duration::from_secs(5);
const MAX_SESSIONS: usize = 65_536;
const MAX_ROWS: usize = 1_000_000;
const MAX_METADATA_BYTES: usize = 65_536;
const MAX_DIAGNOSTICS: usize = 32;
const MAX_EPOCH_MS: i64 = 253_402_300_799_999;
/// Separate budget for retained graph allocations; input and SQLite's owned
/// image are additional allocations. Main also budgets snapshot acquisition.
pub const MAX_DECODED_BYTES: u64 = 128 * 1024 * 1024;

/// Content-free reasons. A failed inspection never establishes absence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnapshotError {
    InvalidImage,
    UnsupportedFormat,
    UnsupportedSchema,
    InvalidGraph,
    InvalidRecord,
    ResourceLimit,
    DeadlineExceeded,
    SqliteFailure,
    SourceTooLarge { actual: u64, max: u64 },
    RecordTooLarge { actual: u64, max: u64 },
}
impl SnapshotError {
    fn provider(self) -> ProviderError {
        match self {
            Self::SourceTooLarge { actual, max } => ProviderError::SourceTooLarge { actual, max },
            Self::RecordTooLarge { actual, max } => ProviderError::RecordTooLarge { actual, max },
            other => ProviderError::StructuralFatal(format!("ZCode snapshot rejected: {other:?}")),
        }
    }
}
type Result<T> = std::result::Result<T, SnapshotError>;

/// Absence is authoritative only in a completed graph scan, never on a limit,
/// unsupported record, missing table, failed read, or elapsed deadline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Presence {
    Present,
    ConfirmedAbsent,
    Unknown,
}

#[derive(Clone)]
pub struct ZCodeSession {
    pub native_id: String,
    pub parent_native_id: Option<String>,
    pub project_id: Option<String>,
    pub directory: Option<String>,
    /// Observed opaque metadata; never treated as an application/format version.
    pub version: Option<String>,
    pub time_created: Option<i64>,
    pub time_updated: Option<i64>,
    /// Revert meaning is unknown. Every scan re-derives the current rows.
    pub has_revert: bool,
    identity: ProviderSessionIdentity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MessageRole {
    User,
    Assistant,
}
impl MessageRole {
    fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Assistant => "assistant",
        }
    }
}

/// Provider payload types remain inside the independent provider boundary.
/// Unknown additive fields are ignored; unknown roles/part kinds defer the
/// whole affected message rather than publishing a shortened replacement.
#[derive(Deserialize)]
struct MessageData {
    role: MessageRole,
}
#[derive(Clone)]
pub enum PartData {
    Text {
        text: String,
    },
    Reasoning {
        text: String,
    },
    Tool {
        call_id: String,
        tool: String,
        state: ToolState,
    },
    File {
        filename: Option<String>,
        mime: Option<String>,
        url: Option<String>,
    },
    StepStart {},
    StepFinish {},
    Timeline {},
    Compaction {},
    Unknown,
}
#[derive(Clone, Deserialize)]
pub struct ToolState {
    pub status: String,
    #[serde(default)]
    pub input: Option<Box<RawValue>>,
    #[serde(default)]
    pub output: Option<Box<RawValue>>,
    #[serde(default)]
    pub error: Option<String>,
}
impl ToolState {
    fn activity_status(&self) -> ToolActivityStatus {
        match self.status.as_str() {
            "completed" => ToolActivityStatus::Success,
            "error" => ToolActivityStatus::Error,
            _ => ToolActivityStatus::Unknown,
        }
    }
}
#[derive(Deserialize)]
struct PartTag {
    #[serde(rename = "type")]
    kind: String,
}
#[derive(Deserialize)]
struct TextData {
    text: String,
}
#[derive(Deserialize)]
struct ToolData {
    #[serde(rename = "callID")]
    call_id: String,
    tool: String,
    state: ToolState,
}
#[derive(Deserialize)]
struct FileData {
    #[serde(default)]
    filename: Option<String>,
    #[serde(default)]
    mime: Option<String>,
    #[serde(default)]
    url: Option<String>,
}
fn decode_part(raw: &str) -> std::result::Result<PartData, serde_json::Error> {
    let tag: PartTag = serde_json::from_str(raw)?;
    Ok(match tag.kind.as_str() {
        "text" => PartData::Text {
            text: serde_json::from_str::<TextData>(raw)?.text,
        },
        "reasoning" => PartData::Reasoning {
            text: serde_json::from_str::<TextData>(raw)?.text,
        },
        "tool" => {
            let data: ToolData = serde_json::from_str(raw)?;
            PartData::Tool {
                call_id: data.call_id,
                tool: data.tool,
                state: data.state,
            }
        }
        "file" => {
            let data: FileData = serde_json::from_str(raw)?;
            PartData::File {
                filename: data.filename,
                mime: data.mime,
                url: data.url,
            }
        }
        "step-start" => PartData::StepStart {},
        "step-finish" => PartData::StepFinish {},
        "timeline" => PartData::Timeline {},
        "compaction" => PartData::Compaction {},
        _ => PartData::Unknown,
    })
}
// Borrow only the shared builder's candidate keys. Unknown input properties
// (including arbitrarily large nested arrays) are skipped by serde, never
// expanded into an unbounded per-tool Value tree.
#[derive(Deserialize)]
struct ActivityInput<'a> {
    #[serde(default, borrow)]
    path: Option<&'a RawValue>,
    #[serde(default, borrow)]
    file_path: Option<&'a RawValue>,
    #[serde(default, borrow, rename = "filePath")]
    file_path_camel: Option<&'a RawValue>,
    #[serde(default, borrow)]
    target: Option<&'a RawValue>,
    #[serde(default, borrow)]
    command: Option<&'a RawValue>,
    #[serde(default, borrow)]
    cmd: Option<&'a RawValue>,
    #[serde(default, borrow)]
    url: Option<&'a RawValue>,
    #[serde(default, borrow)]
    query: Option<&'a RawValue>,
    #[serde(default, borrow)]
    pattern: Option<&'a RawValue>,
    #[serde(default, borrow)]
    glob: Option<&'a RawValue>,
    #[serde(default, borrow)]
    glob_pattern: Option<&'a RawValue>,
    #[serde(default, borrow)]
    regex: Option<&'a RawValue>,
    #[serde(default, borrow)]
    description: Option<&'a RawValue>,
}
fn activity_input(raw: &RawValue) -> Result<Value> {
    match raw.get().trim_start().as_bytes().first() {
        Some(b'"') => serde_json::from_str::<String>(raw.get())
            .map(Value::String)
            .map_err(|_| SnapshotError::InvalidRecord),
        Some(b'{') => {
            let fields: ActivityInput<'_> =
                serde_json::from_str(raw.get()).map_err(|_| SnapshotError::InvalidRecord)?;
            let mut object = serde_json::Map::new();
            for (key, value) in [
                ("path", fields.path),
                ("file_path", fields.file_path),
                ("filePath", fields.file_path_camel),
                ("target", fields.target),
                ("command", fields.command),
                ("cmd", fields.cmd),
                ("url", fields.url),
                ("query", fields.query),
                ("pattern", fields.pattern),
                ("glob", fields.glob),
                ("glob_pattern", fields.glob_pattern),
                ("regex", fields.regex),
                ("description", fields.description),
            ] {
                if let Some(value) = value
                    && value.get().trim_start().starts_with('"')
                {
                    let text: String = serde_json::from_str(value.get())
                        .map_err(|_| SnapshotError::InvalidRecord)?;
                    object.insert(key.into(), Value::String(text));
                }
            }
            Ok(Value::Object(object))
        }
        _ => Ok(Value::Null),
    }
}
#[derive(Clone)]
pub struct ZCodePart {
    pub native_id: String,
    pub sequence: u64,
    pub time_created: Option<i64>,
    pub time_updated: Option<i64>,
    pub data: PartData,
}
#[derive(Clone)]
pub struct ZCodeMessage {
    pub native_id: String,
    /// Injective product namespace for the port's native-message key. Native
    /// resume IDs remain exact separate facts; no path or installation enters it.
    pub message_key: String,
    pub session_native_id: String,
    pub sequence: u64,
    pub time_created: Option<i64>,
    pub time_updated: Option<i64>,
    pub role: MessageRole,
    pub parts: Vec<ZCodePart>,
}

/// A private source graph, not a public CLI/protocol payload. Construction and
/// completeness are private so callers cannot fabricate a complete-scan grant.
pub struct ZCodeSnapshot {
    sessions: Vec<ZCodeSession>,
    messages: Vec<ZCodeMessage>,
    message_ids: BTreeSet<String>,
    part_ids: BTreeSet<String>,
    skipped_messages: usize,
    diagnostics: Vec<String>,
}
impl fmt::Debug for ZCodeSnapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ZCodeSnapshot")
            .field("sessions", &self.sessions.len())
            .field("messages", &self.messages.len())
            .field("parts", &self.part_ids.len())
            .field("complete", &self.is_complete())
            .field("skipped_messages", &self.skipped_messages)
            .finish()
    }
}
impl ZCodeSnapshot {
    pub fn sessions(&self) -> &[ZCodeSession] {
        &self.sessions
    }
    pub fn messages(&self) -> &[ZCodeMessage] {
        &self.messages
    }
    pub fn is_complete(&self) -> bool {
        self.skipped_messages == 0
    }
    pub fn skipped_messages(&self) -> usize {
        self.skipped_messages
    }
    pub fn session_presence(&self, id: &str) -> Presence {
        self.presence(
            id,
            self.sessions.iter().any(|session| session.native_id == id),
        )
    }
    pub fn message_presence(&self, id: &str) -> Presence {
        self.presence(id, self.message_ids.contains(id))
    }
    pub fn part_presence(&self, id: &str) -> Presence {
        self.presence(id, self.part_ids.contains(id))
    }
    fn presence(&self, id: &str, found: bool) -> Presence {
        if native_id(id).is_err() {
            Presence::Unknown
        } else if found {
            Presence::Present
        } else if self.is_complete() {
            Presence::ConfirmedAbsent
        } else {
            Presence::Unknown
        }
    }
}

#[derive(Default)]
pub struct ZCodeAdapter;
impl ZCodeAdapter {
    pub fn new() -> Self {
        Self
    }
    /// A caller's original deadline covers inspection and all sink emissions.
    /// Failure requires discarding staging, including any previously emitted events.
    pub fn parse_with_deadline(
        &self,
        bytes: &[u8],
        sink: &mut dyn CanonicalEventSink,
        end: Instant,
    ) -> std::result::Result<ParseReport, ProviderError> {
        let graph = inspect_snapshot(bytes, end).map_err(SnapshotError::provider)?;
        emit_snapshot(&graph, sink, end)
    }
}
impl ProviderAdapter for ZCodeAdapter {
    fn provider_id(&self) -> &str {
        PROVIDER_ID
    }
    fn manifest(&self) -> AdapterManifest {
        // Main owns the capability/consumption registry. Never borrow OpenCode's
        // identity, capabilities, maturity, certification, or fixture evidence.
        manifest_for(
            PROVIDER_ID,
            Some(1),
            &[
                "requires a caller-acquired standalone logical SQLite image including committed WAL",
                "SQLite graph evidence has no continuous source-byte span",
                "reasoning and tool/file payloads are not conversation prose",
                "empty messages retain native identity for activity anchors",
                "session.version and revert meanings are unknown; scans always re-derive current rows",
                "hard deletion requires an entirely completed supported graph scan",
                "live source acquisition, source discovery and native resume are separate integrations",
            ],
        )
    }
    fn probe(&self, bytes: &[u8]) -> std::result::Result<ProbeResult, ProviderError> {
        if !bytes.starts_with(b"SQLite format 3\0") {
            return Err(ProviderError::AmbiguousVariant(
                "not a ZCode SQLite image".into(),
            ));
        }
        let end = Instant::now() + DEFAULT_BUDGET;
        let db = open_image(bytes, end).map_err(SnapshotError::provider)?;
        schema(&db, end).map_err(|error| {
            if error == SnapshotError::UnsupportedSchema {
                ProviderError::AmbiguousVariant("no complete ZCode graph schema".into())
            } else {
                error.provider()
            }
        })?;
        Ok(ProbeResult {
            variant_id: VARIANT_ID.into(),
            confidence: Confidence::Confirmed,
            matched_evidence: vec![
                "standalone SQLite image".into(),
                "session/message/part/session_entry tables and required sequence/identity columns"
                    .into(),
            ],
            unmatched_evidence: Vec::new(),
        })
    }
    fn parse(
        &self,
        bytes: &[u8],
        sink: &mut dyn CanonicalEventSink,
    ) -> std::result::Result<ParseReport, ProviderError> {
        let end = Instant::now() + DEFAULT_BUDGET;
        self.parse_with_deadline(bytes, sink, end)
    }
    fn probe_source(
        &self,
        source: &dyn ReadOnlySource,
    ) -> std::result::Result<ProbeResult, ProviderError> {
        // Explicit until the main-owned manifest registers ZCode as whole SQLite.
        self.probe(&read_image(source)?)
    }
    fn parse_source(
        &self,
        source: &dyn ReadOnlySource,
        sink: &mut dyn CanonicalEventSink,
    ) -> std::result::Result<ParseReport, ProviderError> {
        let end = Instant::now() + DEFAULT_BUDGET;
        let bytes = read_image(source)?;
        self.parse_with_deadline(&bytes, sink, end)
    }
}
fn read_image(source: &dyn ReadOnlySource) -> std::result::Result<Vec<u8>, ProviderError> {
    read_bounded_source(source, MAX_SQLITE_BYTES)
        .map_err(|error| match error {
            ProviderError::SourceTooLarge { .. } => error,
            _ => ProviderError::StructuralFatal("ZCode snapshot reader failed".into()),
        })
        .and_then(|bytes| {
            if bytes.len() as u64 != source.len() {
                Err(ProviderError::StructuralFatal(
                    "ZCode snapshot length changed or read was incomplete".into(),
                ))
            } else {
                Ok(bytes)
            }
        })
}
fn time(end: Instant) -> Result<()> {
    if Instant::now() >= end {
        Err(SnapshotError::DeadlineExceeded)
    } else {
        Ok(())
    }
}
fn sql(error: rusqlite::Error, end: Instant) -> SnapshotError {
    let _ = error; // No SQL, source paths, payloads or backend strings in errors.
    if Instant::now() >= end {
        SnapshotError::DeadlineExceeded
    } else {
        SnapshotError::SqliteFailure
    }
}
fn open_image(bytes: &[u8], end: Instant) -> Result<Connection> {
    time(end)?;
    if bytes.len() as u64 > MAX_SQLITE_BYTES {
        return Err(SnapshotError::SourceTooLarge {
            actual: bytes.len() as u64,
            max: MAX_SQLITE_BYTES,
        });
    }
    if bytes.len() < 100 || !bytes.starts_with(b"SQLite format 3\0") {
        return Err(SnapshotError::InvalidImage);
    }
    let encoded_page = u16::from_be_bytes([bytes[16], bytes[17]]);
    let page_size = if encoded_page == 1 {
        65_536
    } else {
        usize::from(encoded_page)
    };
    if !(512..=65_536).contains(&page_size)
        || !page_size.is_power_of_two()
        || !bytes.len().is_multiple_of(page_size)
    {
        return Err(SnapshotError::InvalidImage);
    }
    if !matches!((bytes[18], bytes[19]), (1, 1) | (2, 2))
        || !matches!(u32::from_be_bytes(bytes[44..48].try_into().unwrap()), 1..=4)
        || !matches!(u32::from_be_bytes(bytes[56..60].try_into().unwrap()), 1..=3)
    {
        return Err(SnapshotError::UnsupportedFormat);
    }
    let mut db = Connection::open_in_memory().map_err(|error| sql(error, end))?;
    // Backup API images may retain WAL format flags although their committed
    // pages are already complete. sqlite3_deserialize requires rollback flags.
    // Change only SQLite's owned copy via a bounded infallible byte reader; the
    // input remains byte-identical. This cannot establish provenance: callers
    // must supply the verified logical image, never a raw WAL main-file copy.
    let mut prefix = bytes[..20].to_vec();
    prefix[18] = 1;
    prefix[19] = 1;
    let reader = prefix.as_slice().chain(&bytes[20..]);
    db.deserialize_read_exact(MAIN_DB, reader, bytes.len(), true)
        .map_err(|error| sql(error, end))?;
    db.busy_timeout(Duration::ZERO)
        .map_err(|error| sql(error, end))?;
    db.progress_handler(1000, Some(move || Instant::now() >= end))
        .map_err(|error| sql(error, end))?;
    db.execute_batch("PRAGMA query_only=ON; PRAGMA trusted_schema=OFF; PRAGMA temp_store=MEMORY;")
        .map_err(|error| sql(error, end))?;
    time(end)?;
    Ok(db)
}
fn schema(db: &Connection, end: Instant) -> Result<()> {
    for (table, columns) in [
        (
            "session",
            &[
                "id",
                "parent_id",
                "project_id",
                "directory",
                "version",
                "time_created",
                "time_updated",
                "revert",
            ][..],
        ),
        (
            "message",
            &[
                "id",
                "session_id",
                "data",
                "sequence",
                "time_created",
                "time_updated",
            ][..],
        ),
        (
            "part",
            &[
                "id",
                "message_id",
                "session_id",
                "data",
                "sequence",
                "time_created",
                "time_updated",
            ][..],
        ),
        ("session_entry", &[][..]),
    ] {
        time(end)?;
        let ordinary: bool = db.query_row(
            "SELECT EXISTS(SELECT 1 FROM pragma_table_list WHERE schema='main' AND name=?1 AND type='table')",
            [table], |row| row.get(0),
        ).map_err(|error| sql(error, end))?;
        if !ordinary {
            return Err(SnapshotError::UnsupportedSchema);
        }
        let mut statement = db
            .prepare("SELECT name,hidden FROM pragma_table_xinfo(?1)")
            .map_err(|error| sql(error, end))?;
        let mut rows = statement.query([table]).map_err(|error| sql(error, end))?;
        let mut visible = BTreeSet::new();
        let mut count = 0;
        while let Some(row) = rows.next().map_err(|error| sql(error, end))? {
            time(end)?;
            count += 1;
            if count > 256 {
                return Err(SnapshotError::UnsupportedSchema);
            }
            let name: String = row.get(0).map_err(|error| sql(error, end))?;
            let hidden: i64 = row.get(1).map_err(|error| sql(error, end))?;
            if hidden == 0 {
                visible.insert(name);
            }
        }
        if columns.iter().any(|name| !visible.contains(*name)) {
            return Err(SnapshotError::UnsupportedSchema);
        }
    }
    Ok(())
}
fn native_id(id: &str) -> Result<()> {
    StableId::native_checked(IdKind::Message, id)
        .map(|_| ())
        .map_err(|_| SnapshotError::InvalidGraph)
}
fn message_key(id: &str) -> Result<String> {
    native_id(id)?;
    let key = format!("zcode:{id}");
    native_id(&key)?;
    Ok(key)
}
fn text<'a>(row: &'a Row<'_>, column: usize, end: Instant) -> Result<&'a str> {
    match row.get_ref(column).map_err(|error| sql(error, end))? {
        ValueRef::Text(bytes) => {
            if bytes.len() as u64 > STREAM_RECORD_MAX_BYTES {
                return Err(SnapshotError::RecordTooLarge {
                    actual: bytes.len() as u64,
                    max: STREAM_RECORD_MAX_BYTES,
                });
            }
            std::str::from_utf8(bytes).map_err(|_| SnapshotError::InvalidRecord)
        }
        _ => Err(SnapshotError::InvalidRecord),
    }
}
fn optional_text(row: &Row<'_>, column: usize, end: Instant) -> Result<Option<String>> {
    if matches!(
        row.get_ref(column).map_err(|error| sql(error, end))?,
        ValueRef::Null
    ) {
        return Ok(None);
    }
    let value = text(row, column, end)?;
    if value.len() > MAX_METADATA_BYTES {
        return Err(SnapshotError::ResourceLimit);
    }
    Ok(Some(value.into()))
}
fn epoch(row: &Row<'_>, column: usize, end: Instant) -> Result<Option<i64>> {
    match row.get_ref(column).map_err(|error| sql(error, end))? {
        ValueRef::Null => Ok(None),
        ValueRef::Integer(value) if (0..=MAX_EPOCH_MS).contains(&value) => Ok(Some(value)),
        _ => Err(SnapshotError::InvalidRecord),
    }
}
fn sequence(row: &Row<'_>, column: usize, end: Instant) -> Result<u64> {
    match row.get_ref(column).map_err(|error| sql(error, end))? {
        ValueRef::Integer(value) if value >= 0 => Ok(value as u64),
        _ => Err(SnapshotError::InvalidGraph),
    }
}
struct Budget {
    decoded: u64,
    end: Instant,
}
impl Budget {
    fn charge(&mut self, bytes: usize) -> Result<()> {
        time(self.end)?;
        self.decoded = self
            .decoded
            .checked_add(bytes as u64)
            .ok_or(SnapshotError::ResourceLimit)?;
        if self.decoded > MAX_DECODED_BYTES {
            return Err(SnapshotError::ResourceLimit);
        }
        Ok(())
    }
}
struct PendingMessage {
    native_id: String,
    session: String,
    sequence: u64,
    created: Option<i64>,
    updated: Option<i64>,
    role: Option<MessageRole>,
    parts: Vec<ZCodePart>,
    invalid: bool,
}
fn diagnostic(values: &mut Vec<String>, reason: &'static str) {
    if values.len() < MAX_DIAGNOSTICS {
        values.push(reason.into());
    }
}

/// Inspect all graph rows under one original deadline. This is the independent
/// DB-only session inventory/deletion seam. An error returns no snapshot/proof;
/// recoverable content skips return an incomplete graph with unknown absence.
pub fn inspect_snapshot(bytes: &[u8], end: Instant) -> Result<ZCodeSnapshot> {
    let db = open_image(bytes, end)?;
    schema(&db, end)?;
    let integrity: String = db
        .query_row("PRAGMA quick_check(1)", [], |row| row.get(0))
        .map_err(|error| sql(error, end))?;
    if integrity != "ok" {
        return Err(SnapshotError::InvalidImage);
    }
    let mut budget = Budget { decoded: 0, end };
    let mut sessions = BTreeMap::new();
    // Sort retained native facts in Rust, not full JSON rows in SQLite's temp
    // sorter. This prevents an additional database-sized temporary allocation.
    let mut statement = db.prepare("SELECT id,parent_id,project_id,directory,version,time_created,time_updated,revert FROM session")
        .map_err(|error| sql(error, end))?;
    let mut rows = statement.query([]).map_err(|error| sql(error, end))?;
    while let Some(row) = rows.next().map_err(|error| sql(error, end))? {
        time(end)?;
        if sessions.len() >= MAX_SESSIONS {
            return Err(SnapshotError::ResourceLimit);
        }
        let id = text(row, 0, end)?.to_string();
        native_id(&id)?;
        let parent = optional_text(row, 1, end)?;
        if let Some(parent) = &parent {
            native_id(parent)?;
        }
        if parent.as_ref() == Some(&id) {
            return Err(SnapshotError::InvalidGraph);
        }
        let project = optional_text(row, 2, end)?;
        let directory = optional_text(row, 3, end)?.filter(|value| !value.trim().is_empty());
        let version = optional_text(row, 4, end)?;
        let has_revert = match row.get_ref(7).map_err(|error| sql(error, end))? {
            ValueRef::Null => false,
            _ => {
                let revert = text(row, 7, end)?;
                serde_json::from_str::<Box<RawValue>>(revert)
                    .map_err(|_| SnapshotError::InvalidRecord)?;
                budget.charge(revert.len())?;
                true
            }
        };
        budget.charge(
            std::mem::size_of::<ZCodeSession>() * 2
                + 256
                + id.len() * 3
                + parent.as_ref().map_or(0, String::len)
                + project.as_ref().map_or(0, String::len)
                + directory.as_ref().map_or(0, |value| value.len() * 2)
                + version.as_ref().map_or(0, String::len),
        )?;
        let session = ZCodeSession {
            native_id: id.clone(),
            parent_native_id: parent,
            project_id: project,
            directory: directory.clone(),
            version,
            time_created: epoch(row, 5, end)?,
            time_updated: epoch(row, 6, end)?,
            has_revert,
            identity: ProviderSessionIdentity {
                source_key: id.clone(),
                observation: ProviderSessionObservation {
                    provider_session_id: MetadataResolution::Resolved(id.clone()),
                    original_working_directory: directory
                        .clone()
                        .map(MetadataResolution::Resolved)
                        .unwrap_or_default(),
                    pair_observed: directory.is_some(),
                    multi_session: false,
                },
            },
        };
        if sessions.insert(id, session).is_some() {
            return Err(SnapshotError::InvalidGraph);
        }
    }
    // Preserve dangling session parents, but a cycle in the observed rows is
    // structurally contradictory. No parent session becomes a message edge.
    let mut validated = BTreeSet::new();
    for id in sessions.keys() {
        let mut seen = BTreeSet::new();
        let mut cursor = Some(id.as_str());
        while let Some(id) = cursor {
            time(end)?;
            if validated.contains(id) {
                break;
            }
            if !seen.insert(id) {
                return Err(SnapshotError::InvalidGraph);
            }
            cursor = sessions
                .get(id)
                .and_then(|session| session.parent_native_id.as_deref());
        }
        validated.extend(seen);
    }
    let mut pending = BTreeMap::new();
    let mut diagnostics = Vec::new();
    let mut statement = db
        .prepare("SELECT id,session_id,sequence,time_created,time_updated,data FROM message")
        .map_err(|error| sql(error, end))?;
    let mut rows = statement.query([]).map_err(|error| sql(error, end))?;
    let mut orders = BTreeSet::new();
    while let Some(row) = rows.next().map_err(|error| sql(error, end))? {
        time(end)?;
        if pending.len() >= MAX_ROWS {
            return Err(SnapshotError::ResourceLimit);
        }
        let id = text(row, 0, end)?.to_string();
        message_key(&id)?;
        let session = text(row, 1, end)?.to_string();
        if !sessions.contains_key(&session) {
            return Err(SnapshotError::InvalidGraph);
        }
        let order = sequence(row, 2, end)?;
        if !orders.insert((session.clone(), order)) {
            return Err(SnapshotError::InvalidGraph);
        }
        let data = text(row, 5, end)?;
        budget.charge(
            std::mem::size_of::<PendingMessage>() * 2
                + 256
                + data.len()
                + id.len() * 4
                + session.len() * 2,
        )?;
        let role = serde_json::from_str::<MessageData>(data)
            .ok()
            .map(|data| data.role);
        if role.is_none() {
            diagnostic(
                &mut diagnostics,
                "ZCode message payload unsupported or malformed; deferred",
            );
        }
        let message = PendingMessage {
            native_id: id.clone(),
            session,
            sequence: order,
            created: epoch(row, 3, end)?,
            updated: epoch(row, 4, end)?,
            role,
            parts: Vec::new(),
            invalid: role.is_none(),
        };
        if pending.insert(id, message).is_some() {
            return Err(SnapshotError::InvalidGraph);
        }
    }
    let message_ids = pending.keys().cloned().collect();
    let mut part_ids = BTreeSet::new();
    let mut orders = BTreeSet::new();
    let mut statement = db
        .prepare(
            "SELECT id,message_id,session_id,sequence,time_created,time_updated,data FROM part",
        )
        .map_err(|error| sql(error, end))?;
    let mut rows = statement.query([]).map_err(|error| sql(error, end))?;
    while let Some(row) = rows.next().map_err(|error| sql(error, end))? {
        time(end)?;
        if part_ids.len() >= MAX_ROWS {
            return Err(SnapshotError::ResourceLimit);
        }
        let id = text(row, 0, end)?.to_string();
        native_id(&id)?;
        if !part_ids.insert(id.clone()) {
            return Err(SnapshotError::InvalidGraph);
        }
        let message_id = text(row, 1, end)?;
        let message = pending
            .get_mut(message_id)
            .ok_or(SnapshotError::InvalidGraph)?;
        if text(row, 2, end)? != message.session {
            return Err(SnapshotError::InvalidGraph);
        }
        let order = sequence(row, 3, end)?;
        if !orders.insert((message_id.to_string(), order)) {
            return Err(SnapshotError::InvalidGraph);
        }
        let created = epoch(row, 4, end)?;
        let updated = epoch(row, 5, end)?;
        let raw = text(row, 6, end)?;
        budget.charge(
            std::mem::size_of::<ZCodePart>() * 2
                + 256
                + raw.len()
                + id.len() * 2
                + message_id.len(),
        )?;
        let data = decode_part(raw)
            .ok()
            .filter(|data| !matches!(data, PartData::Unknown));
        let Some(data) = data else {
            message.invalid = true;
            diagnostic(
                &mut diagnostics,
                "ZCode part payload unsupported or malformed; whole message deferred",
            );
            continue;
        };
        if let PartData::Tool {
            call_id,
            tool,
            state,
        } = &data
            && (native_id(call_id).is_err()
                || tool.trim().is_empty()
                || tool.len() > MAX_METADATA_BYTES
                || state.status.trim().is_empty()
                || state
                    .input
                    .as_ref()
                    .is_some_and(|raw| activity_input(raw).is_err()))
        {
            message.invalid = true;
            diagnostic(
                &mut diagnostics,
                "ZCode tool payload malformed; whole message deferred",
            );
            continue;
        }
        message.parts.push(ZCodePart {
            native_id: id,
            sequence: order,
            time_created: created,
            time_updated: updated,
            data,
        });
    }
    let mut messages = Vec::new();
    let mut skipped_messages = 0;
    for (_, mut pending) in pending {
        time(end)?;
        if pending.invalid {
            skipped_messages += 1;
            continue;
        }
        pending.parts.sort_by_key(|part| part.sequence);
        let mut text_bytes = 0u64;
        let mut text_parts = 0u64;
        for part in &pending.parts {
            if let PartData::Text { text } = &part.data {
                text_bytes += text.len() as u64 + u64::from(text_parts != 0);
                text_parts += 1;
            }
        }
        if text_bytes > STREAM_RECORD_MAX_BYTES {
            return Err(SnapshotError::RecordTooLarge {
                actual: text_bytes,
                max: STREAM_RECORD_MAX_BYTES,
            });
        }
        messages.push(ZCodeMessage {
            message_key: message_key(&pending.native_id)?,
            native_id: pending.native_id,
            session_native_id: pending.session,
            sequence: pending.sequence,
            time_created: pending.created,
            time_updated: pending.updated,
            role: pending.role.ok_or(SnapshotError::InvalidRecord)?,
            parts: pending.parts,
        });
    }
    messages.sort_by(|left, right| {
        left.session_native_id
            .cmp(&right.session_native_id)
            .then(left.sequence.cmp(&right.sequence))
    });
    time(end)?;
    Ok(ZCodeSnapshot {
        sessions: sessions.into_values().collect(),
        messages,
        message_ids,
        part_ids,
        skipped_messages,
        diagnostics,
    })
}

fn emit_snapshot(
    graph: &ZCodeSnapshot,
    sink: &mut dyn CanonicalEventSink,
    end: Instant,
) -> std::result::Result<ParseReport, ProviderError> {
    let mut report = ParseReport {
        skipped: graph.skipped_messages,
        diagnostics: graph.diagnostics.clone(),
        ..ParseReport::default()
    };
    match graph.sessions.as_slice() {
        [session] => {
            report.session_native_id = Some(session.native_id.clone());
            report.session_observation = session.identity.observation.clone();
        }
        [] => {}
        _ => {
            report.session_observation = ProviderSessionObservation {
                provider_session_id: MetadataResolution::Ambiguous,
                original_working_directory: MetadataResolution::Ambiguous,
                pair_observed: false,
                multi_session: true,
            }
        }
    }
    for message in &graph.messages {
        time(end).map_err(SnapshotError::provider)?;
        let session = graph
            .sessions
            .binary_search_by(|session| session.native_id.cmp(&message.session_native_id))
            .ok()
            .map(|index| &graph.sessions[index])
            .ok_or_else(|| SnapshotError::InvalidGraph.provider())?;
        let text = message
            .parts
            .iter()
            .filter_map(|part| match &part.data {
                PartData::Text { text } => Some(text.as_str()),
                _ => None,
            })
            .collect::<Vec<_>>()
            .join("\n");
        if text.len() as u64 > STREAM_RECORD_MAX_BYTES {
            return Err(SnapshotError::RecordTooLarge {
                actual: text.len() as u64,
                max: STREAM_RECORD_MAX_BYTES,
            }
            .provider());
        }
        let timestamp = message.time_created.map(epoch_ms_utc);
        let seq =
            u32::try_from(report.committed).map_err(|_| SnapshotError::ResourceLimit.provider())?;
        sink.emit_message(MessageEvent {
            session: Some(&session.identity),
            seq,
            native_id: &message.message_key,
            parent_native_id: None,
            role: message.role.as_str(),
            text: &text,
            timestamp: timestamp.as_deref(),
            is_sidechain: session.parent_native_id.is_some(),
            span: None,
        })
        .map_err(|_| {
            ProviderError::StructuralFatal("ZCode canonical message sink rejected staging".into())
        })?;
        report.committed += 1;
        for part in &message.parts {
            time(end).map_err(SnapshotError::provider)?;
            let (name, input, status) = match &part.data {
                PartData::Tool { tool, state, .. } => (
                    tool.as_str(),
                    state
                        .input
                        .as_ref()
                        .map(|input| activity_input(input))
                        .transpose()
                        .map_err(SnapshotError::provider)?
                        .unwrap_or(Value::Null),
                    state.activity_status(),
                ),
                PartData::Reasoning { .. } => {
                    ("reasoning", Value::Null, ToolActivityStatus::Unknown)
                }
                PartData::File { .. } => ("file", Value::Null, ToolActivityStatus::Unknown),
                _ => continue,
            };
            sink.emit_activity(ToolActivityEvent {
                message_native_id: &message.message_key,
                activity: build_tool_activity(
                    name,
                    if session.parent_native_id.is_some() {
                        ToolActivityActor::Subagent
                    } else {
                        ToolActivityActor::Main
                    },
                    &input,
                    status,
                ),
            })
            .map_err(|_| {
                ProviderError::StructuralFatal(
                    "ZCode canonical activity sink rejected staging".into(),
                )
            })?;
        }
    }
    time(end).map_err(SnapshotError::provider)?;
    Ok(report)
}

/// Exact millisecond UTC projection. The raw integer remains available in the
/// private graph; Gregorian arithmetic is bounded to nonnegative four-digit years.
fn epoch_ms_utc(ms: i64) -> String {
    let days = ms / 86_400_000;
    let daytime = ms % 86_400_000;
    let shifted = days + 719_468;
    let era = shifted / 146_097;
    let era_day = shifted % 146_097;
    let era_year = (era_day - era_day / 1460 + era_day / 36524 - era_day / 146096) / 365;
    let mut year = era_year + era * 400;
    let year_day = era_day - (365 * era_year + era_year / 4 - era_year / 100);
    let month_prime = (5 * year_day + 2) / 153;
    let day = year_day - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    if month <= 2 {
        year += 1;
    }
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{:03}Z",
        daytime / 3_600_000,
        daytime % 3_600_000 / 60_000,
        daytime % 60_000 / 1000,
        daytime % 1000
    )
}
