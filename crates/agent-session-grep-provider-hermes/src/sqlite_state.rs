//! Hermes `state.db` SQLite variant (`hermes/sqlite-state-v1`).
//!
//! Reads the databases Hermes writes at `~/.hermes/state.db` and
//! `~/.hermes/profiles/<name>/state.db`: `sessions(id, started_at REAL, ...)`
//! plus `messages(id, session_id, role, content, tool_calls, tool_call_id,
//! tool_name, timestamp REAL, reasoning?)`. The byte-stream contract means the
//! adapter sees the verified snapshot bytes, not a path: profile separation is
//! a *source* fact (each `state.db` is its own document and the composition
//! root derives the installation namespace from the source path), so equal
//! native ids in two profiles never collapse into one canonical Session.
//!
//! Deliberate boundaries (each one is a decision, not an oversight):
//!
//! * **Read-only snapshot.** The adapter never opens the source database. It
//!   copies the received bytes to a private temp file, opens that copy with
//!   `SQLITE_OPEN_READONLY`, `busy_timeout`, `PRAGMA query_only = ON` and one
//!   pinned read transaction, and deletes the copy afterwards. Source
//!   `state.db`/`-wal`/`-shm` are untouched, and production capture already
//!   pins a single logical snapshot (`adapters-sqlite::source_fs::capture`), so
//!   a concurrent committed write cannot change what this parse observes.
//! * **Message identity is not fabricated.** `messages.id` is a per-database
//!   rowid: it is reused after row deletion and is not unique across profiles.
//!   Canonical message identity adopts native ids verbatim *without* a
//!   provider namespace, so adopting a rowid would merge unrelated messages
//!   from different profiles onto one entity (see the recorded
//!   file-scoped-native-id decision for `pi` in
//!   `docs/product/PROVIDER-BETA-READINESS.md`). Messages therefore report an
//!   empty `native_id` and the composition root derives document-scoped
//!   unstable ids. Rowids are preserved verbatim in the diagnostics that name
//!   a row; they are never rewritten, zero-padded or hashed.
//! * **Tool calls are observations, never authority.** Both documented shapes
//!   (`{name, arguments}` and `{id, function: {name, arguments}}`) are decoded
//!   under explicit bounds and accounted per session. Every call/result
//!   association is `authoritative: false`: no native call id is synthesized,
//!   no parent edge is created and no `ToolActivityEvent` is emitted, so the
//!   capability matrix keeps `tool_activity: Unsupported`.
//! * **Time.** `started_at` and `timestamp` are REAL unix seconds; both are
//!   normalized to epoch milliseconds and rendered as
//!   `YYYY-MM-DDTHH:MM:SS.mmmZ`. A NULL `messages.timestamp` stays NULL - the
//!   session's `started_at` is never used as a message-timestamp fallback.
//! * **Bounds are honest.** Rows, sessions, one cell, the total materialized
//!   cell bytes and the per-message tool-call count are all capped; exceeding
//!   any of them fails the source explicitly instead of truncating it.

use agent_session_grep_ports::{
    CanonicalEventSink, Confidence, MessageEvent, MetadataResolution, ParseReport, ProbeResult,
    ProviderError, ProviderSessionIdentity, ProviderSessionObservation, SQLITE_MAX_SOURCE_BYTES,
};
use rusqlite::types::ValueRef;
use rusqlite::{Connection, OpenFlags, OptionalExtension, Row};

/// Variant id surfaced in probe results.
pub(crate) const VARIANT_ID: &str = "hermes/sqlite-state-v1";

/// Every SQLite database starts with this header (100-byte header, first 16).
pub(crate) const SQLITE_MAGIC: &[u8] = b"SQLite format 3\0";

/// Upper bound for the orphan-message census (a diagnostic count, not a read).
const MAX_ORPHAN_CENSUS: u64 = 1_000;

/// Bounds for one probe/parse.
///
/// The defaults are the production limits. They stay injectable so the failure
/// path of every bound is pinned by a small synthetic fixture instead of a
/// multi-megabyte one - a bound that is never exercised is not a bound.
#[derive(Clone, Copy)]
struct Limits {
    max_source_bytes: u64,
    max_sessions: u64,
    max_messages: u64,
    max_cell_bytes: u64,
    max_total_cell_bytes: u64,
    max_tool_calls_per_message: usize,
    max_total_tool_calls: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_source_bytes: SQLITE_MAX_SOURCE_BYTES,
            max_sessions: 4_096,
            max_messages: 250_000,
            // 8 MiB per cell: the same order as the record-stream cap for line
            // formats, and larger than any single Hermes message body.
            max_cell_bytes: 8 * 1024 * 1024,
            max_total_cell_bytes: 64 * 1024 * 1024,
            max_tool_calls_per_message: 32,
            max_total_tool_calls: 200_000,
        }
    }
}

/// `sessions` columns this variant requires to identify the format.
const REQUIRED_SESSION_COLUMNS: &[&str] = &["id", "started_at"];
/// `messages` columns this variant requires to identify the format.
const REQUIRED_MESSAGE_COLUMNS: &[&str] = &[
    "id",
    "session_id",
    "role",
    "content",
    "tool_calls",
    "tool_call_id",
    "tool_name",
    "timestamp",
];

/// True when `bytes` start with the SQLite header.
pub(crate) fn has_sqlite_header(bytes: &[u8]) -> bool {
    bytes.starts_with(SQLITE_MAGIC)
}

/// Structural classification of the two tables this variant needs.
struct Schema {
    /// `messages.reasoning` is optional upstream metadata.
    has_reasoning: bool,
}

/// A table name is a table (not an index/view) with its column list.
fn table_columns(conn: &Connection, table: &str) -> Result<Option<Vec<String>>, ProviderError> {
    let exists: Option<i64> = conn
        .query_row(
            "SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = ?1 COLLATE BINARY LIMIT 1",
            [table],
            |row| row.get(0),
        )
        .optional()
        .map_err(sql_error)?;
    if exists.is_none() {
        return Ok(None);
    }
    let mut statement = conn
        .prepare("SELECT name FROM pragma_table_info(?1)")
        .map_err(sql_error)?;
    let names = statement
        .query_map([table], |row| row.get::<_, String>(0))
        .map_err(sql_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(sql_error)?;
    Ok(Some(names))
}

fn missing_columns(present: &[String], required: &[&str]) -> Vec<String> {
    required
        .iter()
        .filter(|column| !present.iter().any(|name| name == *column))
        .map(|column| (*column).to_string())
        .collect()
}

/// Validate the Hermes state schema, returning the optional-column view.
fn require_schema(conn: &Connection) -> Result<Schema, ProviderError> {
    let sessions = table_columns(conn, "sessions")?.ok_or_else(|| {
        ProviderError::StructuralFatal("hermes state.db has no `sessions` table".into())
    })?;
    let messages = table_columns(conn, "messages")?.ok_or_else(|| {
        ProviderError::StructuralFatal("hermes state.db has no `messages` table".into())
    })?;
    let mut missing = missing_columns(&sessions, REQUIRED_SESSION_COLUMNS);
    missing.extend(missing_columns(&messages, REQUIRED_MESSAGE_COLUMNS));
    if !missing.is_empty() {
        return Err(ProviderError::StructuralFatal(format!(
            "hermes state.db schema is missing key column(s): {}",
            missing.join(", ")
        )));
    }
    Ok(Schema {
        has_reasoning: messages.iter().any(|name| name == "reasoning"),
    })
}

fn sql_error(error: rusqlite::Error) -> ProviderError {
    // SQLite errors here name only the private temp copy this adapter created;
    // the captured source path never reaches this connection.
    ProviderError::StructuralFatal(format!("hermes state.db query failed: {error}"))
}

/// Probe the SQLite variant: schema shape only, never row content.
pub(crate) fn probe(bytes: &[u8]) -> Result<ProbeResult, ProviderError> {
    probe_with_limits(bytes, &Limits::default())
}

fn probe_with_limits(bytes: &[u8], limits: &Limits) -> Result<ProbeResult, ProviderError> {
    if !has_sqlite_header(bytes) {
        return Err(ProviderError::AmbiguousVariant(
            "not a SQLite database (missing magic header)".into(),
        ));
    }
    if bytes.len() as u64 > limits.max_source_bytes {
        return Err(ProviderError::SourceTooLarge {
            actual: bytes.len() as u64,
            max: limits.max_source_bytes,
        });
    }

    let db = open_readonly_from_bytes(bytes)?;
    let conn = &db.conn;

    let mut matched = vec!["SQLite magic header detected".to_string()];
    let mut unmatched = Vec::new();

    let Some(sessions) = table_columns(conn, "sessions")? else {
        return Err(ProviderError::AmbiguousVariant(
            "no `sessions` table found - not a Hermes state.db".into(),
        ));
    };
    let Some(messages) = table_columns(conn, "messages")? else {
        return Err(ProviderError::AmbiguousVariant(
            "no `messages` table found - not a Hermes state.db".into(),
        ));
    };
    matched.push(format!("`sessions` table ({} columns)", sessions.len()));
    matched.push(format!("`messages` table ({} columns)", messages.len()));

    let mut missing = missing_columns(&sessions, REQUIRED_SESSION_COLUMNS);
    missing.extend(missing_columns(&messages, REQUIRED_MESSAGE_COLUMNS));
    if !missing.is_empty() {
        return Err(ProviderError::AmbiguousVariant(format!(
            "Hermes state.db schema is missing key column(s): {}",
            missing.join(", ")
        )));
    }
    matched.push("sessions(id, started_at) + messages(id, session_id, role, content, tool_calls, tool_call_id, tool_name, timestamp) present".into());
    if messages.iter().any(|name| name == "reasoning") {
        matched.push("messages.reasoning column present".into());
    } else {
        unmatched.push("messages.reasoning column absent (optional)".into());
    }

    let session_rows = bounded_count(conn, "SELECT 1 FROM sessions", limits.max_sessions)?;
    let message_rows = bounded_count(conn, "SELECT 1 FROM messages", limits.max_messages)?;
    matched.push(format!(
        "at most {session_rows} session row(s) and {message_rows} message row(s)"
    ));
    if session_rows == 0 {
        unmatched.push("`sessions` currently has no rows".into());
    }

    Ok(ProbeResult {
        variant_id: VARIANT_ID.to_string(),
        confidence: Confidence::Confirmed,
        matched_evidence: matched,
        unmatched_evidence: unmatched,
    })
}

/// Count rows without materializing them, capped at `cap + 1`.
fn bounded_count(conn: &Connection, select_one: &str, cap: u64) -> Result<u64, ProviderError> {
    let sql = format!("SELECT count(*) FROM (SELECT 1 FROM ({select_one}) LIMIT ?1)");
    let count: i64 = conn
        .query_row(&sql, [cap.saturating_add(1) as i64], |row| row.get(0))
        .map_err(sql_error)?;
    Ok(count.max(0) as u64)
}

/// One raw cell value, materialized under the byte budget.
enum Cell {
    Null,
    Integer(i64),
    Real(f64),
    Bytes(Vec<u8>),
}

/// Materialization budget for one database.
struct Materialization {
    limits: Limits,
    cell_bytes: u64,
    tool_calls: u64,
}

impl Materialization {
    fn new(limits: &Limits) -> Self {
        Self {
            limits: *limits,
            cell_bytes: 0,
            tool_calls: 0,
        }
    }

    fn charge_cell(&mut self, actual: u64) -> Result<(), ProviderError> {
        if actual > self.limits.max_cell_bytes {
            return Err(ProviderError::RecordTooLarge {
                actual,
                max: self.limits.max_cell_bytes,
            });
        }
        self.cell_bytes = self.cell_bytes.saturating_add(actual);
        if self.cell_bytes > self.limits.max_total_cell_bytes {
            return Err(ProviderError::SourceTooLarge {
                actual: self.cell_bytes,
                max: self.limits.max_total_cell_bytes,
            });
        }
        Ok(())
    }

    fn charge_tool_calls(&mut self, actual: usize) -> Result<(), ProviderError> {
        if actual > self.limits.max_tool_calls_per_message {
            return Err(ProviderError::RecordTooLarge {
                actual: actual as u64,
                max: self.limits.max_tool_calls_per_message as u64,
            });
        }
        self.tool_calls = self.tool_calls.saturating_add(actual as u64);
        if self.tool_calls > self.limits.max_total_tool_calls {
            return Err(ProviderError::SourceTooLarge {
                actual: self.tool_calls,
                max: self.limits.max_total_tool_calls,
            });
        }
        Ok(())
    }
}

/// Read one cell, charging its byte length before copying it.
fn read_cell(
    row: &Row<'_>,
    index: usize,
    budget: &mut Materialization,
) -> Result<Cell, ProviderError> {
    let value = row.get_ref(index).map_err(sql_error)?;
    let len = match value {
        ValueRef::Null => 0,
        ValueRef::Integer(_) | ValueRef::Real(_) => 8,
        ValueRef::Text(bytes) | ValueRef::Blob(bytes) => bytes.len() as u64,
    };
    budget.charge_cell(len)?;
    Ok(match value {
        ValueRef::Null => Cell::Null,
        ValueRef::Integer(value) => Cell::Integer(value),
        ValueRef::Real(value) => Cell::Real(value),
        ValueRef::Text(bytes) | ValueRef::Blob(bytes) => Cell::Bytes(bytes.to_vec()),
    })
}

/// Text cell -> UTF-8 string. NULL is absent; numbers are a wrong SQLite type.
fn text_cell(cell: &Cell) -> Result<Option<&str>, &'static str> {
    match cell {
        Cell::Null => Ok(None),
        Cell::Bytes(bytes) => std::str::from_utf8(bytes)
            .map(Some)
            .map_err(|_| "invalid UTF-8"),
        Cell::Integer(_) | Cell::Real(_) => Err("non-text SQLite type"),
    }
}

/// REAL/INTEGER unix seconds -> epoch milliseconds (nearest millisecond).
fn seconds_to_epoch_millis(value: f64) -> Option<i64> {
    if !value.is_finite() {
        return None;
    }
    let millis = value * 1_000.0;
    if millis < i64::MIN as f64 || millis >= i64::MAX as f64 {
        return None;
    }
    Some(millis.round() as i64)
}

/// Timestamp cell -> normalized UTC instant. NULL stays absent; a text or
/// non-finite value is a row-level defect the caller reports and skips.
fn timestamp_cell(cell: &Cell) -> Result<Option<String>, &'static str> {
    let millis = match cell {
        Cell::Null => return Ok(None),
        Cell::Integer(value) => seconds_to_epoch_millis(*value as f64),
        Cell::Real(value) => seconds_to_epoch_millis(*value),
        Cell::Bytes(_) => return Err("non-numeric SQLite type"),
    };
    millis
        .map(format_epoch_millis_utc)
        .map(Some)
        .ok_or("non-finite or out-of-range unix seconds")
}

/// Format epoch milliseconds as `YYYY-MM-DDTHH:MM:SS.mmmZ` in UTC using the
/// civil-from-days algorithm (Howard Hinnant, public domain).
fn format_epoch_millis_utc(millis: i64) -> String {
    let seconds = millis.div_euclid(1_000);
    let millis_part = millis.rem_euclid(1_000);
    let days = seconds.div_euclid(86_400);
    let rem = seconds.rem_euclid(86_400);
    let (hour, minute, second) = (rem / 3_600, (rem % 3_600) / 60, rem % 60);

    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    format!("{year:04}-{m:02}-{d:02}T{hour:02}:{minute:02}:{second:02}.{millis_part:03}Z")
}

/// One decoded tool call: an observation used for accounting only.
struct DecodedCall {
    native_call_id: Option<String>,
    name: String,
    /// `"compact"` (`{name, arguments}`) or `"function"` (OpenAI shape).
    shape: &'static str,
}

/// Decode `messages.tool_calls` (JSON text) in both documented shapes.
///
/// Row-level problems (malformed JSON, wrong shape) leave the message intact
/// and are reported through `defect`; only the explicit tool-call budget fails
/// the source, never a silent truncation.
fn decode_tool_calls(
    raw: Option<&str>,
    budget: &mut Materialization,
    defect: &mut Option<&'static str>,
) -> Result<Vec<DecodedCall>, ProviderError> {
    let Some(raw) = raw else {
        return Ok(Vec::new());
    };
    let value: serde_json::Value = match serde_json::from_str(raw) {
        Ok(value) => value,
        Err(_) => {
            *defect = Some("malformed JSON");
            return Ok(Vec::new());
        }
    };
    let serde_json::Value::Array(items) = value else {
        *defect = Some("not a JSON array");
        return Ok(Vec::new());
    };
    budget.charge_tool_calls(items.len())?;
    let mut calls = Vec::with_capacity(items.len());
    for item in &items {
        let serde_json::Value::Object(map) = item else {
            *defect = Some("call entry is not a JSON object");
            return Ok(Vec::new());
        };
        let function = map.get("function").unwrap_or(item);
        let serde_json::Value::Object(function) = function else {
            *defect = Some("`function` is not a JSON object");
            return Ok(Vec::new());
        };
        let Some(name) = function.get("name").and_then(serde_json::Value::as_str) else {
            *defect = Some("call has no `name` string");
            return Ok(Vec::new());
        };
        let native_call_id = match map.get("id") {
            None | Some(serde_json::Value::Null) => None,
            Some(serde_json::Value::String(id)) => Some(id.clone()),
            Some(_) => {
                *defect = Some("`id` is not a string");
                return Ok(Vec::new());
            }
        };
        calls.push(DecodedCall {
            native_call_id,
            name: name.to_string(),
            shape: if map.contains_key("function") {
                "function"
            } else {
                "compact"
            },
        });
    }
    Ok(calls)
}

/// Tool-call accounting for one session. Every association basis is recorded
/// with `authoritative = false`; nothing here can create identity.
#[derive(Default)]
struct ToolAccounting {
    compact_calls: u64,
    function_calls: u64,
    observed_id: u64,
    ambiguous_id: u64,
    unmatched_id: u64,
    name_only: u64,
    ambiguous_name: u64,
    unmatched_name: u64,
    missing_identity: u64,
}

impl ToolAccounting {
    fn record_calls(&mut self, calls: &[DecodedCall]) {
        self.compact_calls += calls.iter().filter(|c| c.shape == "compact").count() as u64;
        self.function_calls += calls.iter().filter(|c| c.shape == "function").count() as u64;
    }
}

/// A tool call emitted by an assistant row, in emission order.
struct PendingCall {
    native_call_id: Option<String>,
    name: String,
}

/// Classify one `tool` row against the calls seen so far. The basis names match
/// the frozen synthetic probe vocabulary; none of them is authoritative.
fn association_basis(
    tool_call_id: Option<&str>,
    tool_name: Option<&str>,
    previous: &[PendingCall],
    accounting: &mut ToolAccounting,
) {
    let basis = match (tool_call_id, tool_name) {
        (Some(call_id), _) => {
            let found = previous
                .iter()
                .filter(|call| call.native_call_id.as_deref() == Some(call_id))
                .count();
            match found {
                0 => "unmatched_id",
                1 => "observed_id",
                _ => "ambiguous_id",
            }
        }
        (None, Some(name)) => {
            let found = previous.iter().filter(|call| call.name == name).count();
            match found {
                0 => "unmatched_name",
                1 => "name_only",
                _ => "ambiguous_name",
            }
        }
        (None, None) => "missing_identity",
    };
    match basis {
        "observed_id" => accounting.observed_id += 1,
        "ambiguous_id" => accounting.ambiguous_id += 1,
        "unmatched_id" => accounting.unmatched_id += 1,
        "name_only" => accounting.name_only += 1,
        "ambiguous_name" => accounting.ambiguous_name += 1,
        "unmatched_name" => accounting.unmatched_name += 1,
        _ => accounting.missing_identity += 1,
    }
}

/// Roles the frozen Hermes probe recognizes as conversational records.
fn known_role(role: &str) -> bool {
    matches!(role, "user" | "assistant" | "system" | "developer" | "tool")
}

/// One session's projection state while its messages are walked in order.
struct SessionWalk {
    identity: ProviderSessionIdentity,
    pending_calls: Vec<PendingCall>,
    tool: ToolAccounting,
    emitted: u64,
    skipped: u64,
}

/// Parse one Hermes `state.db` snapshot into canonical messages.
///
/// Sessions are walked in `sessions.id` order; each session's rows follow the
/// frozen probe order `ORDER BY timestamp, id`, and one monotonically
/// increasing source-local `seq` covers the whole document.
pub(crate) fn parse(
    bytes: &[u8],
    sink: &mut dyn CanonicalEventSink,
) -> Result<ParseReport, ProviderError> {
    parse_with_limits(bytes, sink, &Limits::default())
}

fn parse_with_limits(
    bytes: &[u8],
    sink: &mut dyn CanonicalEventSink,
    limits: &Limits,
) -> Result<ParseReport, ProviderError> {
    if !has_sqlite_header(bytes) {
        return Err(ProviderError::StructuralFatal(
            "not a Hermes state.db (missing SQLite header)".into(),
        ));
    }
    if bytes.len() as u64 > limits.max_source_bytes {
        return Err(ProviderError::SourceTooLarge {
            actual: bytes.len() as u64,
            max: limits.max_source_bytes,
        });
    }

    let db = open_readonly_from_bytes(bytes)?;
    let conn = &db.conn;
    let schema = require_schema(conn)?;
    // Count the whole source, including rows no valid session walk will reach.
    // The result is exact only within this hard cap; the smaller orphan census
    // below is diagnostic-only and must not determine ParseReport::skipped.
    let source_message_rows = bounded_count(conn, "SELECT 1 FROM messages", limits.max_messages)?;
    if source_message_rows > limits.max_messages {
        return Err(ProviderError::SourceTooLarge {
            actual: source_message_rows,
            max: limits.max_messages,
        });
    }
    let mut budget = Materialization::new(limits);
    let mut report = ParseReport::default();

    // Rowids are the only durable ordering key, but they are per-database and
    // recycled, so they are observed only: canonical message identity stays
    // document-scoped (composition root) instead of pretending a rowid is a
    // provider-native, cross-profile-stable id.
    report.diagnostics.push(
        "state.db: messages report no adopted native id (`messages.id` is a per-database rowid, \
         reused after deletes and not unique across profiles); the composition root derives \
         document-scoped ids and rowids are kept verbatim where a diagnostic names a row"
            .into(),
    );

    struct SessionRow {
        id: String,
        // text_cell accepts UTF-8 TEXT and BLOB; preserve the storage class
        // when binding the key rather than matching a different session.
        is_blob: bool,
        identity: ProviderSessionIdentity,
    }

    let mut sessions: Vec<SessionRow> = Vec::new();
    {
        let mut session_rows = 0_u64;
        let mut session_ids = std::collections::BTreeSet::new();
        let mut statement = conn
            .prepare("SELECT id, started_at FROM sessions ORDER BY id")
            .map_err(sql_error)?;
        let mut rows = statement.query([]).map_err(sql_error)?;
        while let Some(row) = rows.next().map_err(sql_error)? {
            session_rows += 1;
            if session_rows > limits.max_sessions {
                return Err(ProviderError::SourceTooLarge {
                    actual: session_rows,
                    max: limits.max_sessions,
                });
            }
            let id_cell = read_cell(row, 0, &mut budget)?;
            let started_cell = read_cell(row, 1, &mut budget)?;
            let id = match text_cell(&id_cell) {
                Ok(Some(id)) if !id.trim().is_empty() => id.to_string(),
                Ok(_) => {
                    report.diagnostics.push(
                        "state.db: session row with NULL/blank `id` skipped; its messages are not read"
                            .into(),
                    );
                    continue;
                }
                Err(reason) => {
                    report.diagnostics.push(format!(
                        "state.db: session row with {reason} `id` skipped; its messages are not read"
                    ));
                    continue;
                }
            };
            // Column presence does not guarantee a UNIQUE constraint. Repeated
            // accepted ids would read the same messages twice; unread orphans
            // could then conceal that overcount in the final reconciliation.
            if !session_ids.insert(id.clone()) {
                return Err(ProviderError::StructuralFatal(
                    "hermes state.db has duplicate session ids".into(),
                ));
            }
            // `started_at` is validated and normalized to milliseconds, but is
            // never used as a message-timestamp fallback: a NULL message
            // timestamp is preserved as absent.
            if !matches!(started_cell, Cell::Null) {
                let seconds = match started_cell {
                    Cell::Integer(value) => Some(value as f64),
                    Cell::Real(value) => Some(value),
                    _ => None,
                };
                if seconds.and_then(seconds_to_epoch_millis).is_none() {
                    report.diagnostics.push(format!(
                        "state.db session {id}: `started_at` is not a finite unix-second value; \
                         kept as an observation only"
                    ));
                }
            }
            sessions.push(SessionRow {
                id: id.clone(),
                is_blob: matches!(row.get_ref(0).map_err(sql_error)?, ValueRef::Blob(_)),
                identity: ProviderSessionIdentity {
                    source_key: id.clone(),
                    observation: ProviderSessionObservation {
                        provider_session_id: MetadataResolution::Resolved(id),
                        original_working_directory: MetadataResolution::Missing,
                        pair_observed: false,
                        multi_session: false,
                    },
                },
            });
        }
    }

    let orphan_count = orphan_messages(conn, MAX_ORPHAN_CENSUS)?;
    if orphan_count > 0 {
        report.diagnostics.push(format!(
            "state.db: at least {orphan_count} message row(s) reference no `sessions.id`; they are not read"
        ));
    }

    match sessions.len() {
        0 => report
            .diagnostics
            .push("state.db: no sessions found; nothing to parse".into()),
        1 => {
            let id = sessions[0].id.clone();
            report.session_native_id = Some(id.clone());
            report.session_observation.provider_session_id = MetadataResolution::Resolved(id);
        }
        _ => {
            // Several sessions in one database: each message carries its own
            // membership, and the report level fails closed instead of
            // claiming one native session for the source.
            report.session_native_id = Some(sessions[0].id.clone());
            report.session_observation.provider_session_id = MetadataResolution::Ambiguous;
            report.session_observation.multi_session = true;
        }
    }

    let reasoning_expr = if schema.has_reasoning {
        "reasoning"
    } else {
        "NULL"
    };
    let select_messages = format!(
        "SELECT id, role, content, tool_calls, tool_call_id, tool_name, timestamp, {reasoning_expr}, session_id \
         FROM messages WHERE session_id = ?1 COLLATE BINARY ORDER BY timestamp, id"
    );

    let mut seq: u32 = 0;
    let mut message_rows: u64 = 0;
    for session in &sessions {
        let mut walk = SessionWalk {
            identity: session.identity.clone(),
            pending_calls: Vec::new(),
            tool: ToolAccounting::default(),
            emitted: 0,
            skipped: 0,
        };
        let mut defect_note = Vec::<String>::new();
        let mut statement = conn.prepare(&select_messages).map_err(sql_error)?;
        let session_key = if session.is_blob {
            ValueRef::Blob(session.id.as_bytes())
        } else {
            ValueRef::Text(session.id.as_bytes())
        };
        let mut rows = if session.is_blob {
            statement.query([session.id.as_bytes()])
        } else {
            statement.query([session.id.as_str()])
        }
        .map_err(sql_error)?;
        while let Some(row) = rows.next().map_err(sql_error)? {
            // Numeric affinity can make distinct ids such as "01" and "1"
            // match one row even under COLLATE BINARY. Successful walks must
            // partition rows by the exact observed key, without coercion.
            if row.get_ref(8).map_err(sql_error)? != session_key {
                return Err(ProviderError::StructuralFatal(
                    "hermes state.db has inconsistent session/message ownership".into(),
                ));
            }
            message_rows += 1;
            if message_rows > limits.max_messages {
                return Err(ProviderError::SourceTooLarge {
                    actual: message_rows,
                    max: limits.max_messages,
                });
            }
            let id_cell = read_cell(row, 0, &mut budget)?;
            let role_cell = read_cell(row, 1, &mut budget)?;
            let content_cell = read_cell(row, 2, &mut budget)?;
            let calls_cell = read_cell(row, 3, &mut budget)?;
            let call_id_cell = read_cell(row, 4, &mut budget)?;
            let tool_name_cell = read_cell(row, 5, &mut budget)?;
            let timestamp_value = read_cell(row, 6, &mut budget)?;
            let reasoning_cell = read_cell(row, 7, &mut budget)?;

            let rowid = match id_cell {
                Cell::Integer(value) => value,
                _ => {
                    walk.skipped += 1;
                    defect_note.push("message row with a non-integer `id` skipped".into());
                    continue;
                }
            };
            let role = match text_cell(&role_cell) {
                Ok(Some(role)) if known_role(role) => role.to_string(),
                Ok(Some(_)) => {
                    walk.skipped += 1;
                    defect_note.push(format!(
                        "message id {rowid}: unknown role skipped (role text not echoed)"
                    ));
                    continue;
                }
                Ok(None) => {
                    walk.skipped += 1;
                    defect_note.push(format!("message id {rowid}: NULL role skipped"));
                    continue;
                }
                Err(reason) => {
                    walk.skipped += 1;
                    defect_note.push(format!("message id {rowid}: {reason} in `role`, skipped"));
                    continue;
                }
            };
            let content = match text_cell(&content_cell) {
                Ok(value) => value,
                Err(reason) => {
                    walk.skipped += 1;
                    defect_note.push(format!(
                        "message id {rowid}: {reason} in `content`, skipped"
                    ));
                    continue;
                }
            };
            let reasoning = match text_cell(&reasoning_cell) {
                Ok(value) => value,
                Err(reason) => {
                    walk.skipped += 1;
                    defect_note.push(format!(
                        "message id {rowid}: {reason} in `reasoning`, skipped"
                    ));
                    continue;
                }
            };
            let timestamp = match timestamp_cell(&timestamp_value) {
                Ok(value) => value,
                Err(reason) => {
                    walk.skipped += 1;
                    defect_note.push(format!(
                        "message id {rowid}: {reason} in `timestamp`, skipped"
                    ));
                    continue;
                }
            };

            let mut tool_defect = None;
            let raw_calls = match text_cell(&calls_cell) {
                Ok(value) => value,
                Err(reason) => {
                    tool_defect = Some(if reason == "invalid UTF-8" {
                        "invalid UTF-8"
                    } else {
                        "non-text SQLite type"
                    });
                    None
                }
            };
            let calls = decode_tool_calls(raw_calls, &mut budget, &mut tool_defect)?;
            if let Some(reason) = tool_defect {
                defect_note.push(format!(
                    "message id {rowid}: `tool_calls` {reason}; calls ignored (non-authoritative)"
                ));
            }

            let content = content.filter(|text| !text.trim().is_empty());
            let reasoning = reasoning.filter(|text| !text.trim().is_empty());
            let text = match (content, reasoning) {
                (Some(content), Some(reasoning)) => {
                    format!("[thinking]\n{reasoning}\n[/thinking]\n{content}")
                }
                (Some(content), None) => content.to_string(),
                (None, Some(reasoning)) => format!("[thinking]\n{reasoning}\n[/thinking]"),
                (None, None) => {
                    walk.skipped += 1;
                    defect_note.push(format!(
                        "message id {rowid}: `content` and `reasoning` are both NULL/blank, skipped"
                    ));
                    continue;
                }
            };

            if role == "tool" {
                let call_id = match text_cell(&call_id_cell) {
                    Ok(value) => value,
                    Err(reason) => {
                        defect_note.push(format!(
                            "message id {rowid}: {reason} in `tool_call_id`; association basis \
                             missing_identity (authoritative=false)"
                        ));
                        None
                    }
                };
                let tool_name = match text_cell(&tool_name_cell) {
                    Ok(value) => value.filter(|name| !name.trim().is_empty()),
                    Err(reason) => {
                        defect_note.push(format!(
                            "message id {rowid}: {reason} in `tool_name`; association basis \
                             missing_identity (authoritative=false)"
                        ));
                        None
                    }
                };
                association_basis(call_id, tool_name, &walk.pending_calls, &mut walk.tool);
            } else if role == "assistant" {
                walk.tool.record_calls(&calls);
                walk.pending_calls
                    .extend(calls.iter().map(|call| PendingCall {
                        native_call_id: call.native_call_id.clone(),
                        name: call.name.clone(),
                    }));
            }

            sink.emit_message(MessageEvent {
                session: Some(&walk.identity),
                seq,
                // See the module docs: a rowid is not a canonical native id.
                native_id: "",
                parent_native_id: None,
                role: &role,
                text: &text,
                timestamp: timestamp.as_deref(),
                is_sidechain: false,
                span: None,
            })
            .map_err(|error| ProviderError::StructuralFatal(error.to_string()))?;
            seq = seq.checked_add(1).ok_or_else(|| {
                ProviderError::StructuralFatal("too many Hermes state.db messages".into())
            })?;
            walk.emitted += 1;
            report.committed += 1;
        }
        drop(rows);
        drop(statement);

        report.skipped += walk.skipped as usize;
        report.diagnostics.extend(defect_note);
        let has_tool_observations = walk.tool.compact_calls > 0
            || walk.tool.function_calls > 0
            || walk.tool.missing_identity > 0;
        if has_tool_observations || walk.skipped > 0 || walk.emitted == 0 {
            report.diagnostics.push(format!(
                "state.db session {}: {} message(s) emitted, {} row(s) skipped; tool calls \
                 compact={} function={}; associations (authoritative=false): observed_id={} \
                 name_only={} ambiguous_id={} ambiguous_name={} unmatched_id={} unmatched_name={} \
                 missing_identity={}",
                session.id,
                walk.emitted,
                walk.skipped,
                walk.tool.compact_calls,
                walk.tool.function_calls,
                walk.tool.observed_id,
                walk.tool.name_only,
                walk.tool.ambiguous_id,
                walk.tool.ambiguous_name,
                walk.tool.unmatched_id,
                walk.tool.unmatched_name,
                walk.tool.missing_identity,
            ));
        }
    }

    let unread_message_rows = source_message_rows
        .checked_sub(message_rows)
        .ok_or_else(|| {
            ProviderError::StructuralFatal(
                "hermes state.db message accounting is inconsistent".into(),
            )
        })?;
    // Per-session skips already count visited bad rows. Only the remaining
    // rows (orphans or messages excluded by invalid session ids) are added.
    report.skipped += unread_message_rows as usize;
    if unread_message_rows > 0 {
        report.diagnostics.push(format!(
            "state.db: {unread_message_rows} message row(s) were not read under a valid session id; \
             counted as skipped"
        ));
    }

    Ok(report)
}

/// Bounded census of message rows whose `session_id` matches no `sessions.id`.
fn orphan_messages(conn: &Connection, cap: u64) -> Result<u64, ProviderError> {
    let sql = "SELECT count(*) FROM (SELECT 1 FROM messages m \
               WHERE NOT EXISTS (SELECT 1 FROM sessions s WHERE s.id = m.session_id COLLATE BINARY) \
               LIMIT ?1)";
    let count: i64 = conn
        .query_row(sql, [cap.saturating_add(1) as i64], |row| row.get(0))
        .map_err(sql_error)?;
    Ok(count.max(0) as u64)
}

/// Process-unique suffix for temp file names: pid + atomic counter.
///
/// Wall-clock nanoseconds alone can collide across parallel test threads when
/// the OS clock granularity is coarse, and `File::create` would silently
/// truncate the other thread's copy.
fn temp_file_suffix() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    format!(
        "{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    )
}

/// Deletes the owned temp database copy (and any SQLite sidecar SQLite may
/// have created for it) once the connection is closed.
struct TempDbGuard {
    path: std::path::PathBuf,
}

impl Drop for TempDbGuard {
    fn drop(&mut self) {
        for suffix in ["", "-wal", "-shm", "-journal"] {
            let mut owned_file = self.path.as_os_str().to_os_string();
            owned_file.push(suffix);
            let _ = std::fs::remove_file(std::path::Path::new(&owned_file));
        }
    }
}

/// Read-only connection over a private copy of the received snapshot bytes.
///
/// **Field order is load-bearing.** Struct fields drop in declaration order, so
/// `conn` closes the database before `_guard` unlinks the copy. Windows refuses
/// to delete a file that is still open and `remove_file`'s error is discarded,
/// so the reverse order would leak every copy silently.
struct TempDb {
    conn: Connection,
    _guard: TempDbGuard,
}

impl TempDb {
    /// Path of the private copy backing this connection.
    #[cfg(test)]
    fn temp_path(&self) -> &std::path::Path {
        &self._guard.path
    }
}

/// Copy the snapshot bytes to a private temp file and open them read-only.
///
/// One pinned read transaction is established before any query, so every
/// statement in one probe/parse observes exactly one database state. The source
/// files are never opened: probe/parse cannot write the source database, its
/// WAL or its SHM, and a concurrent committed write cannot change the
/// observation.
fn open_readonly_from_bytes(bytes: &[u8]) -> Result<TempDb, ProviderError> {
    use std::io::Write;

    let temp_path = std::env::temp_dir().join(format!("asg-hermes-{}.db", temp_file_suffix()));
    let guard = TempDbGuard { path: temp_path };
    let mut file =
        std::fs::File::create(&guard.path).map_err(|error| ProviderError::Io(error.to_string()))?;
    file.write_all(bytes)
        .map_err(|error| ProviderError::Io(error.to_string()))?;
    file.sync_all()
        .map_err(|error| ProviderError::Io(error.to_string()))?;
    drop(file);

    let conn = Connection::open_with_flags(
        &guard.path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|error| {
        ProviderError::StructuralFatal(format!("hermes state.db open failed: {error}"))
    })?;
    conn.busy_timeout(std::time::Duration::from_secs(1))
        .map_err(sql_error)?;
    // Pin one read transaction (`BEGIN` + a first read); every later statement
    // in this connection sees that same snapshot.
    conn.execute_batch(
        "PRAGMA query_only = ON; BEGIN; SELECT rootpage FROM sqlite_schema LIMIT 1;",
    )
    .map_err(sql_error)?;

    Ok(TempDb {
        conn,
        _guard: guard,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_session_grep_ports::{PortResult, ToolActivityEvent};

    /// Every emitted message plus the tool activities that must never appear.
    #[derive(Default)]
    struct RecordingSink {
        messages: Vec<Recorded>,
        activities: usize,
    }

    struct Recorded {
        seq: u32,
        native_id: String,
        session: Option<String>,
        role: String,
        text: String,
        timestamp: Option<String>,
    }

    impl CanonicalEventSink for RecordingSink {
        fn emit_message(&mut self, event: MessageEvent<'_>) -> PortResult<()> {
            self.messages.push(Recorded {
                seq: event.seq,
                native_id: event.native_id.to_string(),
                session: event.session.map(|identity| identity.source_key.clone()),
                role: event.role.to_string(),
                text: event.text.to_string(),
                timestamp: event.timestamp.map(str::to_string),
            });
            Ok(())
        }

        fn emit_activity(&mut self, _event: ToolActivityEvent<'_>) -> PortResult<()> {
            self.activities += 1;
            Ok(())
        }
    }

    /// Owned scratch directory for synthetic state.db fixtures.
    struct Scratch {
        dir: std::path::PathBuf,
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn scratch(tag: &str) -> Scratch {
        let dir = std::env::temp_dir().join(format!(
            "asg-hermes-sqlite-test-{tag}-{}",
            temp_file_suffix()
        ));
        std::fs::create_dir_all(&dir).expect("scratch dir");
        Scratch { dir }
    }

    /// Build a closed, single-file state.db from SQL and return its bytes.
    fn state_db(scratch: &Scratch, sql: &str) -> Vec<u8> {
        let path = scratch.dir.join("state.db");
        {
            let conn = Connection::open(&path).expect("open scratch db");
            conn.execute_batch(sql).expect("apply scratch sql");
        }
        std::fs::read(&path).expect("read scratch db")
    }

    const SCHEMA: &str = "CREATE TABLE sessions (id TEXT PRIMARY KEY, started_at REAL);\n\
        CREATE TABLE messages (id INTEGER PRIMARY KEY, session_id TEXT, role TEXT, content TEXT, \
        tool_calls TEXT, tool_call_id TEXT, tool_name TEXT, reasoning TEXT, timestamp REAL);\n";

    fn parse_ok(bytes: &[u8]) -> (ParseReport, RecordingSink) {
        let mut sink = RecordingSink::default();
        let report = parse(bytes, &mut sink).expect("parse must succeed");
        (report, sink)
    }

    fn diagnostics(report: &ParseReport) -> String {
        report.diagnostics.join("\n")
    }

    #[test]
    fn probe_confirms_the_synthetic_state_schema() {
        let scratch = scratch("probe-ok");
        let bytes = state_db(
            &scratch,
            &format!(
                "{SCHEMA}INSERT INTO sessions VALUES ('s1', 1700000000.125);\n\
                 INSERT INTO messages (id, session_id, role, content, timestamp) \
                 VALUES (1, 's1', 'user', 'hello', 1700000001.5);\n"
            ),
        );
        let probe = probe(&bytes).expect("probe must succeed");
        assert_eq!(probe.variant_id, VARIANT_ID);
        assert_eq!(probe.confidence, Confidence::Confirmed);
        assert!(
            probe
                .matched_evidence
                .iter()
                .any(|line| line.contains("`sessions`"))
        );
    }

    #[test]
    fn probe_rejects_bytes_that_are_not_the_hermes_state_schema() {
        // A SQLite database with an unrelated schema is another provider's
        // business: the hermes variant must decline, not guess.
        let unrelated = scratch("probe-unrelated");
        let bytes = state_db(&unrelated, "CREATE TABLE unrelated (key TEXT);\n");
        assert!(matches!(
            probe(&bytes),
            Err(ProviderError::AmbiguousVariant(_))
        ));

        // Same table names, missing key columns.
        let partial = scratch("probe-partial");
        let bytes = state_db(
            &partial,
            "CREATE TABLE sessions (id TEXT PRIMARY KEY);\n\
             CREATE TABLE messages (id INTEGER PRIMARY KEY, session_id TEXT);\n",
        );
        assert!(matches!(
            probe(&bytes),
            Err(ProviderError::AmbiguousVariant(_))
        ));

        // The JSON variant is a different byte stream entirely.
        assert!(matches!(
            probe(br#"{"session_id": "s1", "messages": [{"role": "user"}]}"#),
            Err(ProviderError::AmbiguousVariant(_))
        ));
    }

    #[test]
    fn variants_are_mutually_exclusive_per_byte_stream() {
        let scratch = scratch("exclusive");
        let db_bytes = state_db(
            &scratch,
            &format!("{SCHEMA}INSERT INTO sessions VALUES ('s1', NULL);\n"),
        );
        // The SQLite bytes are claimed by the SQLite probe and rejected by the
        // JSON probe; JSON bytes are rejected by the SQLite probe (above). No
        // single byte stream satisfies both claims.
        assert!(probe(&db_bytes).is_ok());
        assert!(super::super::probe_session_json(&db_bytes).is_err());
        // And the explicit ambiguity guard still refuses a hypothetical
        // double-claim instead of picking one.
        assert!(matches!(
            super::super::exclusive_claim(true, true),
            Err(ProviderError::AmbiguousVariant(_))
        ));
        assert!(super::super::exclusive_claim(true, false).is_ok());
        assert!(super::super::exclusive_claim(false, true).is_ok());
        assert!(super::super::exclusive_claim(false, false).is_ok());
    }

    #[test]
    fn parse_orders_by_timestamp_then_id_and_normalizes_seconds() {
        let scratch = scratch("ordering");
        // Inserted out of order: equal timestamps must fall back to the id
        // order, and the later timestamp must come last.
        let bytes = state_db(
            &scratch,
            &format!(
                "{SCHEMA}INSERT INTO sessions VALUES ('s1', 1700000000.125);\n\
                 INSERT INTO messages (id, session_id, role, content, timestamp) \
                 VALUES (3, 's1', 'user', 'third', 1700000005.25);\n\
                 INSERT INTO messages (id, session_id, role, content, timestamp) \
                 VALUES (1, 's1', 'user', 'first', 1700000001.0);\n\
                 INSERT INTO messages (id, session_id, role, content, timestamp) \
                 VALUES (2, 's1', 'assistant', 'second', 1700000001.0);\n"
            ),
        );
        let (report, sink) = parse_ok(&bytes);
        assert_eq!(report.committed, 3);
        assert_eq!(
            sink.messages
                .iter()
                .map(|m| m.text.as_str())
                .collect::<Vec<_>>(),
            vec!["first", "second", "third"]
        );
        assert_eq!(sink.messages[0].seq, 0);
        assert_eq!(sink.messages[1].role, "assistant");
        assert_eq!(sink.messages[2].seq, 2);
        assert_eq!(
            sink.messages[0].timestamp.as_deref(),
            Some("2023-11-14T22:13:21.000Z")
        );
        assert_eq!(
            sink.messages[2].timestamp.as_deref(),
            Some("2023-11-14T22:13:25.250Z")
        );
        // Messages report no adopted native id; the composition root derives a
        // document-scoped identity instead.
        assert!(sink.messages.iter().all(|m| m.native_id.is_empty()));
    }

    #[test]
    fn parse_preserves_null_timestamps_and_reports_rows_without_text() {
        let scratch = scratch("nulls");
        let bytes = state_db(
            &scratch,
            &format!(
                "{SCHEMA}INSERT INTO sessions VALUES ('s1', NULL);\n\
                 INSERT INTO messages (id, session_id, role, content, timestamp) \
                 VALUES (1, 's1', 'user', 'with timestamp', 1700000002.5);\n\
                 INSERT INTO messages (id, session_id, role, content, reasoning, timestamp) \
                 VALUES (2, 's1', 'assistant', NULL, 'reasoning only', NULL);\n\
                 INSERT INTO messages (id, session_id, role, content, timestamp) \
                 VALUES (3, 's1', 'user', NULL, NULL);\n"
            ),
        );
        let (report, sink) = parse_ok(&bytes);
        assert_eq!(report.committed, 2);
        assert_eq!(report.skipped, 1);
        // `ORDER BY timestamp, id` puts NULL timestamps first; the NULL stays
        // absent instead of falling back to the session's started_at.
        assert_eq!(sink.messages[0].timestamp, None);
        assert_eq!(
            sink.messages[0].text,
            "[thinking]\nreasoning only\n[/thinking]"
        );
        assert_eq!(
            sink.messages[1].timestamp.as_deref(),
            Some("2023-11-14T22:13:22.500Z")
        );
        // The body-less row is reported by rowid, never silently dropped.
        assert!(diagnostics(&report).contains("message id 3"));
        assert!(diagnostics(&report).contains("NULL/blank"));
    }

    #[test]
    fn parse_reports_per_message_session_membership_for_several_sessions() {
        let scratch = scratch("multi-session");
        let bytes = state_db(
            &scratch,
            &format!(
                "{SCHEMA}INSERT INTO sessions VALUES ('profile-a', 1700000000.0);\n\
                 INSERT INTO sessions VALUES ('profile-b', 1700000001.0);\n\
                 INSERT INTO messages (id, session_id, role, content, timestamp) \
                 VALUES (1, 'profile-a', 'user', 'from a', 1700000002.0);\n\
                 INSERT INTO messages (id, session_id, role, content, timestamp) \
                 VALUES (2, 'profile-b', 'user', 'from b', 1700000002.0);\n"
            ),
        );
        let (report, sink) = parse_ok(&bytes);
        assert_eq!(report.committed, 2);
        assert!(report.session_observation.multi_session);
        assert_eq!(
            report.session_observation.provider_session_id,
            MetadataResolution::Ambiguous
        );
        assert_eq!(report.session_native_id.as_deref(), Some("profile-a"));
        assert_eq!(
            sink.messages
                .iter()
                .map(|m| m.session.as_deref())
                .collect::<Vec<_>>(),
            vec![Some("profile-a"), Some("profile-b")]
        );
        // Every message carries its own session membership.
        assert_eq!(sink.messages[0].seq, 0);
        assert_eq!(sink.messages[1].seq, 1);
    }

    #[test]
    fn parse_decodes_both_tool_call_shapes_without_claiming_authority() {
        let cases = scratch("tools");
        let rows = r#"
INSERT INTO sessions VALUES ('s1', 1700000000.0);
INSERT INTO messages (id, session_id, role, content, tool_calls, timestamp) VALUES (1, 's1', 'assistant', 'compact call', '[{"name":"read_file","arguments":{"path":"a"}}]', 1700000001.0);
INSERT INTO messages (id, session_id, role, content, tool_calls, timestamp) VALUES (2, 's1', 'assistant', 'openai call', '[{"id":"call-2","function":{"name":"write_file","arguments":{"path":"b"}}}]', 1700000002.0);
INSERT INTO messages (id, session_id, role, content, tool_calls, timestamp) VALUES (3, 's1', 'assistant', 'duplicate ids', '[{"id":"call-dup","name":"dup_a","arguments":{}},{"id":"call-dup","name":"dup_b","arguments":{}}]', 1700000003.0);
INSERT INTO messages (id, session_id, role, content, tool_call_id, timestamp) VALUES (4, 's1', 'tool', 'observed id', 'call-2', 1700000004.0);
INSERT INTO messages (id, session_id, role, content, tool_call_id, timestamp) VALUES (5, 's1', 'tool', 'ambiguous id', 'call-dup', 1700000005.0);
INSERT INTO messages (id, session_id, role, content, tool_name, timestamp) VALUES (6, 's1', 'tool', 'name only', 'read_file', 1700000006.0);
INSERT INTO messages (id, session_id, role, content, tool_call_id, timestamp) VALUES (7, 's1', 'tool', 'unmatched id', 'never-seen', 1700000007.0);
INSERT INTO messages (id, session_id, role, content, tool_name, timestamp) VALUES (8, 's1', 'tool', 'unmatched name', 'never_called', 1700000008.0);
INSERT INTO messages (id, session_id, role, content, timestamp) VALUES (9, 's1', 'tool', 'no identity', 1700000009.0);
"#;
        let bytes = state_db(&cases, &format!("{SCHEMA}{rows}"));
        let (report, sink) = parse_ok(&bytes);
        assert_eq!(report.committed, 9);
        assert_eq!(sink.activities, 0, "tool activity must stay unemitted");
        let notes = diagnostics(&report);
        assert!(notes.contains("compact=3 function=1"), "{notes}");
        assert!(notes.contains("observed_id=1"), "{notes}");
        assert!(notes.contains("ambiguous_id=1"), "{notes}");
        assert!(notes.contains("name_only=1"), "{notes}");
        assert!(notes.contains("unmatched_id=1"), "{notes}");
        assert!(notes.contains("unmatched_name=1"), "{notes}");
        assert!(notes.contains("missing_identity=1"), "{notes}");
        assert!(notes.contains("authoritative=false"), "{notes}");
    }

    #[test]
    fn parse_reports_bad_rows_and_keeps_going() {
        let scratch = scratch("bad-rows");
        // `id` is deliberately not an INTEGER PRIMARY KEY here so a text id can
        // be present at all; the other four rows exercise each defect.
        let bytes = state_db(
            &scratch,
            &format!(
                r#"{SCHEMA}INSERT INTO sessions VALUES ('s1', 1700000000.0);
INSERT INTO messages (id, session_id, role, content, tool_calls, timestamp) VALUES (1, 's1', 'user', 'kept despite bad calls', '{{"broken":', 1700000001.0);
INSERT INTO messages (id, session_id, role, content, timestamp) VALUES (2, 's1', 'wizard', 'unknown role', 1700000002.0);
INSERT INTO messages (id, session_id, role, content, timestamp) VALUES (3, 's1', 'user', CAST(x'ff' AS BLOB), 1700000003.0);
INSERT INTO messages (id, session_id, role, content, timestamp) VALUES (4, 's1', 'user', 'text timestamp', 'not a number');
INSERT INTO messages (id, session_id, role, content) VALUES (5, 's1', NULL, 'null role');
"#
            ),
        );
        let (report, sink) = parse_ok(&bytes);
        assert_eq!(report.committed, 1);
        assert_eq!(sink.messages[0].text, "kept despite bad calls");
        assert_eq!(report.skipped, 4);
        let notes = diagnostics(&report);
        assert!(notes.contains("malformed JSON"), "{notes}");
        assert!(notes.contains("message id 2"), "{notes}");
        assert!(notes.contains("invalid UTF-8"), "{notes}");
        assert!(notes.contains("message id 4"), "{notes}");
        assert!(notes.contains("NULL role"), "{notes}");
    }

    #[test]
    fn parse_accounts_for_all_orphans_beyond_the_diagnostic_census() {
        for count in [
            0,
            1,
            MAX_ORPHAN_CENSUS,
            MAX_ORPHAN_CENSUS + 1,
            MAX_ORPHAN_CENSUS + 2,
        ] {
            let scratch = scratch("orphan-accounting");
            let bytes = state_db(
                &scratch,
                &format!(
                    "{SCHEMA}WITH RECURSIVE ids(id) AS (\
                     SELECT 1 WHERE {count} > 0 UNION ALL SELECT id + 1 FROM ids WHERE id < {count}) \
                     INSERT INTO messages (id, session_id, role, content) \
                     SELECT id, 'missing', 'user', 'omitted orphan body' FROM ids;"
                ),
            );
            let (report, sink) = parse_ok(&bytes);
            assert_eq!((report.committed, report.skipped), (0, count as usize));
            assert!(sink.messages.is_empty());
            let notes = diagnostics(&report);
            if count > 0 {
                let census = count.min(MAX_ORPHAN_CENSUS + 1);
                assert!(
                    notes.contains(&format!("at least {census} message row(s)")),
                    "{notes}"
                );
                assert!(
                    notes.contains(&format!("{count} message row(s) were not read")),
                    "{notes}"
                );
            }
            assert!(!notes.contains("omitted orphan body"), "{notes}");
        }
    }

    #[test]
    fn parse_accounts_for_messages_excluded_by_invalid_session_ids() {
        // No affinity on either key: numbers stay numbers instead of SQLite
        // converting them to valid text before the parser can observe them.
        let schema = SCHEMA
            .replace("id TEXT PRIMARY KEY", "id")
            .replace("session_id TEXT", "session_id");
        for (id, reason) in [
            ("NULL", "NULL/blank"),
            ("''", "NULL/blank"),
            ("'  '", "NULL/blank"),
            ("CAST(x'ff' AS TEXT)", "invalid UTF-8"),
            ("x'ff'", "invalid UTF-8"),
            ("42", "non-text SQLite type"),
            ("1.25", "non-text SQLite type"),
        ] {
            for with_valid_session in [false, true] {
                let scratch = scratch("invalid-session-accounting");
                let mut sql = format!(
                    "{schema}INSERT INTO sessions VALUES ({id}, NULL); \
                     INSERT INTO messages (id, session_id, role, content) VALUES \
                     (1, {id}, 'user', 'omitted invalid-session body'), \
                     (2, {id}, 'assistant', 'another omitted body');"
                );
                if with_valid_session {
                    sql.push_str(
                        "INSERT INTO sessions VALUES ('s1', NULL); \
                         INSERT INTO messages (id, session_id, role, content) \
                         VALUES (3, 's1', 'user', 'kept');",
                    );
                }
                let bytes = state_db(&scratch, &sql);
                let (report, sink) = parse_ok(&bytes);
                let committed = usize::from(with_valid_session);
                assert_eq!((report.committed, report.skipped), (committed, 2), "{id}");
                assert_eq!(sink.messages.len(), committed);
                if with_valid_session {
                    assert_eq!(sink.messages[0].text, "kept");
                    assert_eq!(sink.messages[0].session.as_deref(), Some("s1"));
                    assert_eq!(sink.messages[0].seq, 0);
                    assert!(sink.messages[0].native_id.is_empty());
                }
                let notes = diagnostics(&report);
                assert!(notes.contains(reason), "{notes}");
                assert!(notes.contains("2 message row(s) were not read"), "{notes}");
                assert!(!notes.contains("omitted invalid-session body"), "{notes}");
                assert!(!notes.contains("another omitted body"), "{notes}");
            }
        }
    }

    #[test]
    fn parse_accounts_for_mixed_omissions_and_bad_rows_once() {
        let scratch = scratch("mixed-accounting");
        let bytes = state_db(
            &scratch,
            &format!(
                "{SCHEMA}INSERT INTO sessions VALUES ('s1', NULL), (' ', NULL); \
                 INSERT INTO messages (id, session_id, role, content, tool_calls, timestamp) VALUES \
                 (1, 's1', 'user', 'kept', NULL, NULL), \
                 (2, 's1', 'wizard', NULL, NULL, 'bad timestamp'), \
                 (3, 'missing', 'wizard', 'omitted orphan body', NULL, NULL), \
                 (4, ' ', 'user', 'omitted invalid-session body', NULL, NULL), \
                 (5, 's1', 'assistant', 'kept despite bad calls', '{{', NULL);"
            ),
        );
        let (report, sink) = parse_ok(&bytes);
        assert_eq!((report.committed, report.skipped), (2, 3));
        assert_eq!(sink.messages.len(), report.committed);
        assert_eq!(sink.messages[0].text, "kept");
        assert_eq!(sink.messages[1].text, "kept despite bad calls");
        assert_eq!(sink.messages[1].seq, 1);
        assert!(
            sink.messages
                .iter()
                .all(|message| message.native_id.is_empty())
        );
        let notes = diagnostics(&report);
        assert!(notes.contains("at least 1 message row(s)"), "{notes}");
        assert!(notes.contains("2 message row(s) were not read"), "{notes}");
        assert!(
            notes.contains("2 message(s) emitted, 1 row(s) skipped"),
            "{notes}"
        );
        assert!(notes.contains("malformed JSON"), "{notes}");
        assert!(!notes.contains("omitted orphan body"), "{notes}");
        assert!(!notes.contains("omitted invalid-session body"), "{notes}");
    }

    #[test]
    fn parse_counts_repeated_message_rows_without_deduplication() {
        let scratch = scratch("repeated-message-accounting");
        let schema = SCHEMA.replace("id INTEGER PRIMARY KEY", "id INTEGER");
        let bytes = state_db(
            &scratch,
            &format!(
                "{schema}INSERT INTO sessions VALUES ('s1', NULL); \
                 INSERT INTO messages (id, session_id, role, content) VALUES \
                 (1, 's1', 'user', 'repeated body'), (1, 's1', 'user', 'repeated body');"
            ),
        );
        let (report, sink) = parse_ok(&bytes);
        assert_eq!((report.committed, report.skipped), (2, 0));
        assert_eq!(sink.messages.len(), 2);
        assert_eq!(sink.messages[0].text, sink.messages[1].text);
        assert_eq!((sink.messages[0].seq, sink.messages[1].seq), (0, 1));
        assert!(
            sink.messages
                .iter()
                .all(|message| message.native_id.is_empty())
        );
    }

    #[test]
    fn parse_enforces_full_source_message_limits_including_unread_rows() {
        for owners in [
            vec![],
            vec!["s1"],
            vec!["missing"],
            vec![""],
            vec!["s1", "missing", ""],
        ] {
            let scratch = scratch("source-message-limit");
            let mut sql = format!("{SCHEMA}INSERT INTO sessions VALUES ('s1', NULL), ('', NULL);");
            for (index, owner) in owners.iter().enumerate() {
                sql.push_str(&format!(
                    "INSERT INTO messages (id, session_id, role, content) \
                     VALUES ({}, '{owner}', 'user', 'synthetic body');",
                    index + 1,
                ));
            }
            let bytes = state_db(&scratch, &sql);
            let limits = Limits {
                max_messages: owners.len() as u64,
                ..Limits::default()
            };
            let mut sink = RecordingSink::default();
            let report = parse_with_limits(&bytes, &mut sink, &limits)
                .expect("the exact message limit must be accepted");
            let committed = owners.iter().filter(|owner| **owner == "s1").count();
            assert_eq!(report.committed, committed);
            assert_eq!(report.skipped, owners.len() - committed);
            assert_eq!(sink.messages.len(), committed);
            if !owners.is_empty() {
                let mut sink = RecordingSink::default();
                let smaller = Limits {
                    max_messages: limits.max_messages - 1,
                    ..limits
                };
                let error = parse_with_limits(&bytes, &mut sink, &smaller).expect_err(
                    "an overflow must fail even when only unread rows exceed the limit",
                );
                assert!(
                    matches!(error, ProviderError::SourceTooLarge { actual, max }
                    if actual == limits.max_messages && max == smaller.max_messages)
                );
                assert!(
                    sink.messages.is_empty(),
                    "the census must fail before emission"
                );
            }
        }
    }

    #[test]
    fn parse_enforces_session_limits_including_invalid_rows() {
        let schema = SCHEMA.replace("id TEXT PRIMARY KEY", "id");
        for (first, second) in [
            ("NULL", "NULL"),
            ("''", "'s1'"),
            ("x'ff'", "x'fe'"),
            ("41", "42"),
        ] {
            let scratch = scratch("source-session-limit");
            let bytes = state_db(
                &scratch,
                &format!(
                    "{schema}INSERT INTO sessions VALUES ({first}, NULL), ({second}, NULL); \
                     INSERT INTO messages (id, session_id, role, content) \
                     VALUES (1, {first}, 'user', 'omitted body');"
                ),
            );
            let mut sink = RecordingSink::default();
            let exact = Limits {
                max_sessions: 2,
                ..Limits::default()
            };
            let report = parse_with_limits(&bytes, &mut sink, &exact)
                .expect("the exact session row limit must be accepted");
            assert_eq!((report.committed, report.skipped), (0, 1));
            let smaller = Limits {
                max_sessions: 1,
                ..exact
            };
            assert!(matches!(
                parse_with_limits(&bytes, &mut sink, &smaller),
                Err(ProviderError::SourceTooLarge { actual: 2, max: 1 })
            ));
            assert!(sink.messages.is_empty());
        }
    }

    #[test]
    fn parse_rejects_duplicate_sessions_even_when_orphans_hide_overcounting() {
        let schema = SCHEMA.replace("id TEXT PRIMARY KEY", "id TEXT");
        for duplicate in ["'s1'", "CAST('s1' AS BLOB)"] {
            let scratch = scratch("duplicate-session-accounting");
            let bytes = state_db(
                &scratch,
                &format!(
                    "{schema}INSERT INTO sessions VALUES ('s1', NULL), ({duplicate}, 1.0); \
                     INSERT INTO messages (id, session_id, role, content) VALUES \
                     (1, 's1', 'user', 'kept once'), (2, 'missing', 'user', 'orphan body');"
                ),
            );
            let mut sink = RecordingSink::default();
            let error = parse(&bytes, &mut sink)
                .expect_err("duplicate accepted session ids make the walk ambiguous");
            assert!(matches!(error, ProviderError::StructuralFatal(ref reason)
                if reason.contains("duplicate session id")));
            assert!(
                sink.messages.is_empty(),
                "duplicates must fail before emission"
            );
        }
    }

    #[test]
    fn parse_rejects_coercing_session_matches_even_when_orphans_hide_overcounting() {
        let scratch = scratch("coercing-session-accounting");
        let schema = SCHEMA.replace("session_id TEXT", "session_id NUMERIC");
        let bytes = state_db(
            &scratch,
            &format!(
                "{schema}INSERT INTO sessions VALUES ('01', NULL), ('1', NULL); \
                 INSERT INTO messages (id, session_id, role, content) VALUES \
                 (1, 1, 'user', 'kept once'), (2, 99, 'user', 'orphan body');"
            ),
        );
        let mut sink = RecordingSink::default();
        let error = parse(&bytes, &mut sink)
            .expect_err("numeric affinity must not make two session walks emit the same row");
        assert!(matches!(error, ProviderError::StructuralFatal(ref reason)
            if reason.contains("inconsistent session/message ownership")));
        assert!(sink.messages.is_empty());
    }

    #[test]
    fn parse_preserves_binary_session_keys_without_reading_text_orphans() {
        let scratch = scratch("binary-session-accounting");
        let bytes = state_db(
            &scratch,
            &format!(
                "{SCHEMA}INSERT INTO sessions VALUES (CAST('s1' AS BLOB), NULL), ('s2', NULL); \
                 INSERT INTO messages (id, session_id, role, content) VALUES \
                 (1, CAST('s1' AS BLOB), 'user', 'binary session body'), \
                 (2, 's1', 'user', 'orphan text body'), (3, 's2', 'user', 'text session body');"
            ),
        );
        let (report, sink) = parse_ok(&bytes);
        assert_eq!((report.committed, report.skipped), (2, 1));
        assert_eq!(sink.messages.len(), 2);
        assert!(
            sink.messages
                .iter()
                .any(|message| message.session.as_deref() == Some("s1")
                    && message.text == "binary session body")
        );
        assert!(
            sink.messages
                .iter()
                .any(|message| message.session.as_deref() == Some("s2")
                    && message.text == "text session body")
        );
        assert!(
            !sink
                .messages
                .iter()
                .any(|message| message.text == "orphan text body")
        );
    }

    #[test]
    fn parse_fails_explicitly_when_a_bound_is_exceeded() {
        let cases = scratch("bounds");
        let calls = r#"[{"name":"a","arguments":{}},{"name":"b","arguments":{}}]"#;
        let bytes = state_db(
            &cases,
            &format!(
                "{SCHEMA}INSERT INTO sessions VALUES ('s1', 1700000000.0);\n\
                 INSERT INTO messages (id, session_id, role, content, tool_calls, timestamp) \
                 VALUES (1, 's1', 'assistant', 'two calls', '{calls}', 1700000001.0);\n\
                 INSERT INTO messages (id, session_id, role, content, timestamp) \
                 VALUES (2, 's1', 'user', 'second message', 1700000002.0);\n"
            ),
        );

        let mut sink = RecordingSink::default();
        let tight_tool = Limits {
            max_tool_calls_per_message: 1,
            ..Limits::default()
        };
        assert!(matches!(
            parse_with_limits(&bytes, &mut sink, &tight_tool),
            Err(ProviderError::RecordTooLarge { actual: 2, max: 1 })
        ));

        let mut sink = RecordingSink::default();
        let tight_total_tools = Limits {
            max_total_tool_calls: 1,
            ..Limits::default()
        };
        assert!(matches!(
            parse_with_limits(&bytes, &mut sink, &tight_total_tools),
            Err(ProviderError::SourceTooLarge { max: 1, .. })
        ));

        let mut sink = RecordingSink::default();
        let tight_cell = Limits {
            max_cell_bytes: 4,
            ..Limits::default()
        };
        assert!(matches!(
            parse_with_limits(&bytes, &mut sink, &tight_cell),
            Err(ProviderError::RecordTooLarge { max: 4, .. })
        ));

        let mut sink = RecordingSink::default();
        let tight_total = Limits {
            max_total_cell_bytes: 10,
            ..Limits::default()
        };
        assert!(matches!(
            parse_with_limits(&bytes, &mut sink, &tight_total),
            Err(ProviderError::SourceTooLarge { max: 10, .. })
        ));

        let mut sink = RecordingSink::default();
        let tight_messages = Limits {
            max_messages: 1,
            ..Limits::default()
        };
        assert!(matches!(
            parse_with_limits(&bytes, &mut sink, &tight_messages),
            Err(ProviderError::SourceTooLarge { max: 1, .. })
        ));

        let two_sessions = state_db(
            &scratch("bounds-sessions"),
            &format!(
                "{SCHEMA}INSERT INTO sessions VALUES ('s1', NULL);\n\
                 INSERT INTO sessions VALUES ('s2', NULL);\n"
            ),
        );
        let mut sink = RecordingSink::default();
        let tight_sessions = Limits {
            max_sessions: 1,
            ..Limits::default()
        };
        assert!(matches!(
            parse_with_limits(&two_sessions, &mut sink, &tight_sessions),
            Err(ProviderError::SourceTooLarge { max: 1, .. })
        ));

        // Over-size snapshots fail before any copy is made.
        let mut over_cap = vec![0_u8; 64];
        over_cap[..SQLITE_MAGIC.len()].copy_from_slice(SQLITE_MAGIC);
        let tiny_source = Limits {
            max_source_bytes: 16,
            ..Limits::default()
        };
        let mut sink = RecordingSink::default();
        assert!(matches!(
            parse_with_limits(&over_cap, &mut sink, &tiny_source),
            Err(ProviderError::SourceTooLarge {
                actual: 64,
                max: 16
            })
        ));
        assert!(matches!(
            probe_with_limits(&over_cap, &tiny_source),
            Err(ProviderError::SourceTooLarge {
                actual: 64,
                max: 16
            })
        ));
    }

    #[test]
    fn private_snapshot_copy_is_removed_after_use() {
        let scratch = scratch("cleanup");
        let bytes = state_db(
            &scratch,
            &format!("{SCHEMA}INSERT INTO sessions VALUES ('s1', NULL);\n"),
        );
        let path = {
            let db = open_readonly_from_bytes(&bytes).expect("open private copy");
            let path = db.temp_path().to_path_buf();
            assert!(path.exists(), "copy must exist while the handle lives");
            path
        };
        assert!(
            !path.exists(),
            "the private copy must be unlinked when the handle drops"
        );
    }

    /// Private temp copies must be unlinked after a successful read *and* after
    /// a query error, including the `-wal`/`-shm` files a WAL-mode source makes
    /// SQLite materialize for the copy. Mirrors the contract the other
    /// SQLite-reading provider crates pin.
    fn assert_wal_temp_copy_cleanup(query: &str, should_fail: bool) {
        let scratch = scratch("wal-cleanup");
        let fixture_path = scratch.dir.join("cleanup.db");
        {
            let writer = Connection::open(&fixture_path).expect("wal fixture writer");
            writer
                .execute_batch(
                    "PRAGMA journal_mode=WAL;\
                     CREATE TABLE cleanup_fixture (value INTEGER);\
                     INSERT INTO cleanup_fixture VALUES (7);",
                )
                .expect("wal fixture schema");
            // Dropping the last writer checkpoints the WAL into the main file,
            // exactly like a real source that is at rest when capture reads it.
        }
        let bytes = std::fs::read(&fixture_path).expect("fixture bytes");

        let mut copy_path = None;
        let result = (|| -> Result<i64, ProviderError> {
            let db = open_readonly_from_bytes(&bytes)?;
            let path = db.temp_path().to_path_buf();
            // A real read materializes the private copy's own sidecars: its
            // header still records WAL mode.
            db.conn
                .query_row("SELECT value FROM cleanup_fixture", [], |row| {
                    row.get::<_, i64>(0)
                })
                .map_err(sql_error)?;
            for suffix in ["-wal", "-shm"] {
                let mut sidecar = path.as_os_str().to_os_string();
                sidecar.push(suffix);
                assert!(
                    std::path::Path::new(&sidecar).exists(),
                    "the read-only copy must materialize its own {suffix}"
                );
            }
            copy_path = Some(path);
            // The error case returns while `TempDb` is still the local owner.
            db.conn
                .query_row(query, [], |row| row.get::<_, i64>(0))
                .map_err(sql_error)
        })();
        assert_eq!(result.is_err(), should_fail, "{result:?}");

        let path = copy_path.expect("copy path");
        let mut remaining = Vec::new();
        for suffix in ["", "-wal", "-shm", "-journal"] {
            let mut owned_file = path.as_os_str().to_os_string();
            owned_file.push(suffix);
            let owned_file = std::path::Path::new(&owned_file);
            if owned_file.exists() {
                remaining.push(suffix);
                // Do not leave files behind when the assertion below fails.
                let _ = std::fs::remove_file(owned_file);
            }
        }
        assert!(
            remaining.is_empty(),
            "temporary SQLite files leaked: {remaining:?}"
        );
    }

    #[test]
    fn wal_temp_copy_cleans_sidecars_after_success() {
        assert_wal_temp_copy_cleanup("SELECT value FROM cleanup_fixture", false);
    }

    #[test]
    fn wal_temp_copy_cleans_sidecars_after_query_error() {
        assert_wal_temp_copy_cleanup("SELECT missing_column FROM cleanup_fixture", true);
    }

    #[test]
    fn source_database_files_stay_byte_identical_across_a_concurrent_wal_commit() {
        let scratch = scratch("wal");
        let source_path = scratch.dir.join("state.db");
        let writer = Connection::open(&source_path).expect("writer");
        writer
            .execute_batch(&format!(
                "PRAGMA journal_mode = WAL; PRAGMA wal_autocheckpoint = 0; {SCHEMA}\
                 INSERT INTO sessions VALUES ('s1', 1700000000.0);\n"
            ))
            .expect("wal schema");
        writer
            .execute_batch(
                "INSERT INTO messages (id, session_id, role, content, timestamp) \
                 VALUES (1, 's1', 'user', 'before commit', 1700000001.0);",
            )
            .expect("first row");

        // SQLite appends the sidecar suffixes to the full database file name.
        let wal_path = scratch.dir.join("state.db-wal");
        let shm_path = scratch.dir.join("state.db-shm");
        assert!(
            wal_path.exists() && shm_path.exists(),
            "the synthetic writer must keep a live WAL and SHM"
        );

        // One logical snapshot, exactly like production capture: SQLite writes
        // the currently committed database (WAL frames included) to a single
        // new file, so no racy main/WAL/SHM copy is involved.
        let snapshot_path = scratch.dir.join("snapshot.db");
        writer
            .execute_batch(&format!("VACUUM INTO '{}'", snapshot_path.display()))
            .expect("logical snapshot");
        let snapshot_bytes = std::fs::read(&snapshot_path).expect("snapshot bytes");

        let before = read_source_state(&source_path, &wal_path, &shm_path);
        let (report, sink) = parse_ok(&snapshot_bytes);
        assert_eq!(report.committed, 1);
        assert_eq!(sink.messages[0].text, "before commit");
        let after = read_source_state(&source_path, &wal_path, &shm_path);
        assert_eq!(before, after, "probe/parse must not touch the source files");

        // A concurrent commit changes the source, but a snapshot taken before
        // it keeps observing exactly the same database state.
        writer
            .execute_batch(
                "INSERT INTO messages (id, session_id, role, content, timestamp) \
                 VALUES (2, 's1', 'user', 'after commit', 1700000002.0);",
            )
            .expect("second row");
        let (again_report, again_sink) = parse_ok(&snapshot_bytes);
        assert_eq!(again_report.committed, report.committed);
        assert_eq!(
            again_sink
                .messages
                .iter()
                .map(|m| m.text.as_str())
                .collect::<Vec<_>>(),
            vec!["before commit"]
        );

        // A fresh snapshot does see the new row: the writer's commit is real,
        // only this parse's observation is pinned.
        std::fs::remove_file(&snapshot_path).expect("drop old snapshot");
        writer
            .execute_batch(&format!("VACUUM INTO '{}'", snapshot_path.display()))
            .expect("second logical snapshot");
        let fresh = std::fs::read(&snapshot_path).expect("fresh snapshot bytes");
        let (fresh_report, _) = parse_ok(&fresh);
        assert_eq!(fresh_report.committed, 2);
    }

    /// `(len, mtime, BLAKE3)` per source file; `None` once it does not exist.
    fn read_source_state(
        main: &std::path::Path,
        wal: &std::path::Path,
        shm: &std::path::Path,
    ) -> Vec<Option<(u64, std::time::SystemTime, String)>> {
        [main, wal, shm]
            .into_iter()
            .map(|path| {
                let meta = std::fs::metadata(path).ok()?;
                let bytes = std::fs::read(path).ok()?;
                Some((
                    meta.len(),
                    meta.modified().expect("mtime"),
                    blake3::hash(&bytes).to_hex().to_string(),
                ))
            })
            .collect()
    }
}
