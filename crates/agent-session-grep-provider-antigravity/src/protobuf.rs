//! Bounded reader for the observed Antigravity CLI 1.1.16 Step subset.
//!
//! Field evidence: independently observed synthetic sessions documented at
//! <https://github.com/xhluca/antigravity-session-interoperability/blob/b85c60a1eacd44808fa7b1cffc343e4af936df9d/docs/format.md>.
//! The implementation below is independently written from that wire map; no
//! native database, vendor binding, runtime descriptor or transcript is used.
//! This evidence does not certify other host releases or encrypted loose `.pb`
//! files. Unknown step types/encodings are incomplete, never string-scanned.

use crate::{
    AntigravityObservation, AntigravitySourceFormat, CONVERSATION_VARIANT_ID, MAX_STEPS,
    ParseDeadline,
};
use agent_session_grep_ports::{
    CanonicalEventSink, Confidence, MessageEvent, MetadataResolution, ProbeResult, ProviderError,
    SQLITE_MAX_SOURCE_BYTES, STREAM_RECORD_MAX_BYTES,
};
use rusqlite::{Connection, OptionalExtension, limits::Limit, types::ValueRef};
use std::{ffi::c_void, ops::Deref, ptr::NonNull};

pub(crate) const SQLITE_MAGIC: &[u8] = b"SQLite format 3\0";
const MAX_WIRE_FIELDS: usize = 16_384;
const MAX_FIELD_NUMBER: u64 = (1 << 29) - 1;

struct WireBudget {
    remaining: usize,
    deadline: ParseDeadline,
}
const REQUIRED_STEP_COLUMNS: &[&str] = &[
    "idx",
    "step_type",
    "status",
    "has_subtrajectory",
    "metadata",
    "error_details",
    "permissions",
    "task_details",
    "render_info",
    "step_payload",
    "step_format",
];

fn invalid(reason: &str) -> ProviderError {
    ProviderError::StructuralFatal(format!("Antigravity snapshot: {reason}"))
}

/// A decoded scalar or opaque length-delimited field. Bytes are never promoted
/// to conversation text without a known field path and a validated role/type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireValue<'a> {
    Varint(u64),
    Fixed64(u64),
    Bytes(&'a [u8]),
    Fixed32(u32),
}

/// One wire field and its exact range in the supplied snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WireField<'a> {
    pub number: u32,
    pub value: WireValue<'a>,
    pub span: (u64, u64),
    pub value_span: (u64, u64),
}

fn varint(data: &[u8], cursor: &mut usize) -> Result<u64, ProviderError> {
    let mut value = 0u64;
    for index in 0..10 {
        let byte = *data
            .get(*cursor)
            .ok_or_else(|| invalid("truncated protobuf varint"))?;
        *cursor += 1;
        if index == 9 && byte > 1 {
            return Err(invalid("protobuf varint overflow"));
        }
        value |= u64::from(byte & 0x7f) << (index * 7);
        if byte & 0x80 == 0 {
            if index > 0 && byte == 0 {
                return Err(invalid("noncanonical protobuf varint"));
            }
            return Ok(value);
        }
    }
    Err(invalid("protobuf varint overflow"))
}

fn take<'a>(data: &'a [u8], cursor: &mut usize, length: usize) -> Result<&'a [u8], ProviderError> {
    let end = cursor
        .checked_add(length)
        .ok_or_else(|| invalid("protobuf length overflow"))?;
    let value = data
        .get(*cursor..end)
        .ok_or_else(|| invalid("truncated protobuf field"))?;
    *cursor = end;
    Ok(value)
}

fn fields<'a>(
    data: &'a [u8],
    base: u64,
    remaining: &mut WireBudget,
) -> Result<Vec<WireField<'a>>, ProviderError> {
    remaining.deadline.check()?;
    if data.len() as u64 > STREAM_RECORD_MAX_BYTES {
        return Err(ProviderError::RecordTooLarge {
            actual: data.len() as u64,
            max: STREAM_RECORD_MAX_BYTES,
        });
    }
    let mut result = Vec::new();
    let mut cursor = 0usize;
    while cursor < data.len() {
        remaining.deadline.check()?;
        if remaining.remaining == 0 {
            return Err(invalid("protobuf field count exceeds supported limit"));
        }
        remaining.remaining -= 1;
        let start = cursor;
        let tag = varint(data, &mut cursor)?;
        let number = tag >> 3;
        if number == 0 || number > MAX_FIELD_NUMBER {
            return Err(invalid("invalid protobuf field number"));
        }
        let mut value_start = cursor;
        let value = match tag & 7 {
            0 => WireValue::Varint(varint(data, &mut cursor)?),
            1 => WireValue::Fixed64(u64::from_le_bytes(
                take(data, &mut cursor, 8)?
                    .try_into()
                    .map_err(|_| invalid("invalid fixed64"))?,
            )),
            2 => {
                let length = varint(data, &mut cursor)?;
                if length > STREAM_RECORD_MAX_BYTES {
                    return Err(ProviderError::RecordTooLarge {
                        actual: length,
                        max: STREAM_RECORD_MAX_BYTES,
                    });
                }
                let length = usize::try_from(length)
                    .map_err(|_| invalid("protobuf length exceeds addressable range"))?;
                value_start = cursor;
                WireValue::Bytes(take(data, &mut cursor, length)?)
            }
            5 => WireValue::Fixed32(u32::from_le_bytes(
                take(data, &mut cursor, 4)?
                    .try_into()
                    .map_err(|_| invalid("invalid fixed32"))?,
            )),
            _ => return Err(invalid("unsupported protobuf wire type or group")),
        };
        let position = |offset: usize| {
            base.checked_add(offset as u64)
                .ok_or_else(|| invalid("protobuf span overflow"))
        };
        result
            .try_reserve(1)
            .map_err(|_| ProviderError::Io("bounded protobuf allocation failed".into()))?;
        result.push(WireField {
            number: number as u32,
            value,
            span: (position(start)?, position(cursor)?),
            value_span: (position(value_start)?, position(cursor)?),
        });
    }
    Ok(result)
}

/// Decode only ordinary wire framing/scalars, with a fixed byte/field bound.
/// No recursive schema inference, decompression or UTF-8 string scavenging.
pub fn decode_fields(data: &[u8]) -> Result<Vec<WireField<'_>>, ProviderError> {
    decode_fields_with_deadline(data, ParseDeadline::unlimited())
}
fn decode_fields_with_deadline(
    data: &[u8],
    deadline: ParseDeadline,
) -> Result<Vec<WireField<'_>>, ProviderError> {
    let mut remaining = WireBudget {
        remaining: MAX_WIRE_FIELDS,
        deadline,
    };
    let result = fields(data, 0, &mut remaining)?;
    deadline.check()?;
    Ok(result)
}

fn singular<'a, 'b>(
    values: &'b [WireField<'a>],
    number: u32,
) -> Result<Option<&'b WireField<'a>>, ProviderError> {
    let mut matching = values.iter().filter(|field| field.number == number);
    let first = matching.next();
    if matching.next().is_some() {
        return Err(invalid("duplicate singular protobuf field"));
    }
    Ok(first)
}
fn integer(values: &[WireField<'_>], number: u32) -> Result<Option<u64>, ProviderError> {
    singular(values, number)?
        .map(|field| match field.value {
            WireValue::Varint(value) => Ok(value),
            _ => Err(invalid("protobuf integer has wrong wire type")),
        })
        .transpose()
}
fn nested<'a>(
    values: &[WireField<'a>],
    number: u32,
    remaining: &mut WireBudget,
) -> Result<Option<Vec<WireField<'a>>>, ProviderError> {
    singular(values, number)?
        .map(|field| match field.value {
            WireValue::Bytes(value) => fields(value, field.value_span.0, remaining),
            _ => Err(invalid("protobuf message has wrong wire type")),
        })
        .transpose()
}
type SpannedString<'a> = (&'a str, (u64, u64));

fn string<'a>(
    values: &[WireField<'a>],
    number: u32,
    deadline: ParseDeadline,
) -> Result<Option<SpannedString<'a>>, ProviderError> {
    deadline.check()?;
    let value = singular(values, number)?
        .map(|field| match field.value {
            WireValue::Bytes(value) => Ok((
                std::str::from_utf8(value)
                    .map_err(|_| invalid("invalid UTF-8 in a mapped protobuf string"))?,
                field.value_span,
            )),
            _ => Err(invalid("protobuf string has wrong wire type")),
        })
        .transpose()?;
    deadline.check()?;
    Ok(value)
}

/// Supported Step facts; unknown variants retain their numeric type and no text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedStep<'a> {
    pub step_type: u64,
    pub status: u64,
    pub role: Option<&'static str>,
    pub text: Option<&'a str>,
    pub text_span: Option<(u64, u64)>,
    pub native_message_id: Option<&'a str>,
    pub supported: bool,
}

/// Decode the fixed Step map, validating every known singular field before use.
/// Duplicate identity/status/oneof payloads fail closed. Additive unknown fields
/// remain opaque. Unknown step types cannot become user or assistant messages.
pub fn decode_step(data: &[u8]) -> Result<DecodedStep<'_>, ProviderError> {
    decode_step_with_deadline(data, ParseDeadline::unlimited())
}
fn decode_step_with_deadline(
    data: &[u8],
    deadline: ParseDeadline,
) -> Result<DecodedStep<'_>, ProviderError> {
    deadline.check()?;
    let mut remaining = WireBudget {
        remaining: MAX_WIRE_FIELDS,
        deadline,
    };
    let root = fields(data, 0, &mut remaining)?;
    let step_type = integer(&root, 1)?.ok_or_else(|| invalid("Step type missing"))?;
    let status = integer(&root, 4)?.ok_or_else(|| invalid("Step status missing"))?;
    if let Some(metadata) = singular(&root, 5)?
        && !matches!(metadata.value, WireValue::Bytes(_))
    {
        return Err(invalid("Step metadata has wrong wire type"));
    }
    let payloads = [19, 20, 140]
        .into_iter()
        .map(|number| singular(&root, number))
        .collect::<Result<Vec<_>, _>>()?;
    if payloads.iter().filter(|field| field.is_some()).count() > 1 {
        return Err(invalid("ambiguous Step payload alternatives"));
    }
    let mut result = DecodedStep {
        step_type,
        status,
        role: None,
        text: None,
        text_span: None,
        native_message_id: None,
        supported: false,
    };
    let (payload_number, text_number, role) = match step_type {
        14 => (19, 2, "user"),
        15 => (20, 1, "assistant"),
        132 => {
            let payload = nested(&root, 140, &mut remaining)?
                .ok_or_else(|| invalid("generic-tool payload missing"))?;
            for field in payload.iter().filter(|field| field.number == 1) {
                let WireValue::Bytes(entry) = field.value else {
                    return Err(invalid("generic-tool map has wrong wire type"));
                };
                let entry = fields(entry, field.value_span.0, &mut remaining)?;
                string(&entry, 1, deadline)?;
                string(&entry, 2, deadline)?;
            }
            if let Some(value) = nested(&payload, 2, &mut remaining)? {
                string(&value, 1, deadline)?;
            }
            result.supported = true;
            deadline.check()?;
            return Ok(result);
        }
        _ => return Ok(result),
    };
    let payload = nested(&root, payload_number, &mut remaining)?
        .ok_or_else(|| invalid("mapped Step payload missing"))?;
    let mut text = string(&payload, text_number, deadline)?;
    if step_type == 15 {
        // Field 3 is the documented visible trace, matching JSONL's existing
        // visible-thinking fallback. No raw trace/signature field is decoded.
        let visible_thinking = string(&payload, 3, deadline)?;
        if text.is_none_or(|(value, _)| value.trim().is_empty()) {
            text = visible_thinking;
        }
        let native = string(&payload, 6, deadline)?.map(|(value, _)| value);
        if native.is_some_and(|value| value.len() > 4096 || value.chars().any(char::is_control)) {
            return Err(invalid("malformed native message identity"));
        }
        result.native_message_id = native.filter(|value| !value.trim().is_empty());
        // Calls are metadata until the composition root adopts an anchoring
        // contract. Still validate framing and mapped strings without emitting
        // tool activity or promoting argument/result text to chat messages.
        for field in payload.iter().filter(|field| field.number == 7) {
            let WireValue::Bytes(call) = field.value else {
                return Err(invalid("planner tool call has wrong wire type"));
            };
            let call = fields(call, field.value_span.0, &mut remaining)?;
            string(&call, 1, deadline)?;
            string(&call, 2, deadline)?;
            string(&call, 3, deadline)?;
        }
    }
    result.role = Some(role);
    if let Some((value, span)) = text.filter(|(value, _)| !value.trim().is_empty()) {
        result.text = Some(value);
        result.text_span = Some(span);
    }
    result.supported = true;
    deadline.check()?;
    Ok(result)
}

fn apply_step(
    result: &mut AntigravityObservation,
    step: &DecodedStep<'_>,
    step_index: u64,
    span: Option<(u64, u64)>,
    sink: Option<&mut dyn CanonicalEventSink>,
    deadline: ParseDeadline,
) -> Result<(), ProviderError> {
    deadline.check()?;
    if !step.supported {
        result.incomplete(
            format!("step {step_index}: unsupported stored step type"),
            true,
        );
    } else if !matches!(step.status, 3 | 7) {
        result.incomplete(
            format!("step {step_index}: nonterminal or unknown stored step status"),
            true,
        );
    } else if let (Some(role), Some(text), Some(sink)) = (step.role, step.text, sink) {
        result.emit(
            sink,
            step_index,
            MessageEvent {
                session: None,
                seq: 0,
                native_id: step.native_message_id.unwrap_or(""),
                parent_native_id: None,
                role,
                text,
                timestamp: None,
                is_sidechain: false,
                span,
            },
            deadline,
        )?;
    }
    Ok(())
}

pub(crate) fn parse_step_snapshot(
    bytes: &[u8],
    step_index: u64,
    sink: &mut dyn CanonicalEventSink,
    deadline: ParseDeadline,
) -> Result<AntigravityObservation, ProviderError> {
    let step = decode_step_with_deadline(bytes, deadline)?;
    let mut result = AntigravityObservation::new(AntigravitySourceFormat::ProtobufStep);
    apply_step(
        &mut result,
        &step,
        step_index,
        Some((0, bytes.len() as u64)),
        Some(sink),
        deadline,
    )?;
    deadline.check()?;
    Ok(result)
}

struct SnapshotConnection {
    conn: Connection,
    _progress_deadline: Box<ParseDeadline>,
}
impl SnapshotConnection {
    fn new(conn: Connection, deadline: ParseDeadline) -> Self {
        let progress_deadline = Box::new(deadline);
        // SAFETY: this private connection has no concurrent users. The boxed
        // callback context remains at one address until Drop unregisters it.
        // The callback only reads the deadline and never reenters SQLite.
        unsafe {
            rusqlite::ffi::sqlite3_progress_handler(
                conn.handle(),
                1000,
                Some(progress_deadline_callback),
                (&*progress_deadline as *const ParseDeadline)
                    .cast_mut()
                    .cast::<c_void>(),
            );
        }
        Self {
            conn,
            _progress_deadline: progress_deadline,
        }
    }
}
impl Deref for SnapshotConnection {
    type Target = Connection;
    fn deref(&self) -> &Self::Target {
        &self.conn
    }
}
impl Drop for SnapshotConnection {
    fn drop(&mut self) {
        // SAFETY: the connection/context are alive and no statement escapes
        // this wrapper. Unregister before either field drops on every exit path.
        unsafe {
            rusqlite::ffi::sqlite3_progress_handler(
                self.conn.handle(),
                0,
                None,
                std::ptr::null_mut(),
            );
        }
    }
}
unsafe extern "C" fn progress_deadline_callback(context: *mut c_void) -> std::ffi::c_int {
    // SAFETY: SnapshotConnection owns this immutable, heap-stable context for
    // the full registration lifetime. This callback cannot unwind/reenter SQL.
    let deadline = unsafe { &*context.cast::<ParseDeadline>() };
    std::ffi::c_int::from(deadline.expired())
}

fn decode_buffer(
    bytes: &[u8],
    deadline: ParseDeadline,
) -> Result<rusqlite::serialize::OwnedData, ProviderError> {
    deadline.check()?;
    // SAFETY: open_snapshot validated a nonempty bounded image. Immediately
    // establish the RAII owner before any subsequent deadline can return early.
    let pointer =
        NonNull::new(unsafe { rusqlite::ffi::sqlite3_malloc64(bytes.len() as u64).cast::<u8>() })
            .ok_or_else(|| {
            ProviderError::Io("bounded SQLite decode buffer allocation failed".into())
        })?;
    let owned = unsafe { rusqlite::serialize::OwnedData::from_raw_nonnull(pointer, bytes.len()) };
    // SAFETY: this SQLite allocation has exactly bytes.len() writable bytes,
    // does not alias input, and is private until ownership transfers to SQLite.
    let buffer = unsafe { std::slice::from_raw_parts_mut(pointer.as_ptr(), bytes.len()) };
    for (target, source) in buffer.chunks_mut(64 * 1024).zip(bytes.chunks(64 * 1024)) {
        deadline.check()?;
        target.copy_from_slice(source);
    }
    buffer[18] = 1;
    buffer[19] = 1;
    deadline.check()?;
    Ok(owned)
}

fn table_columns(
    conn: &Connection,
    name: &str,
    deadline: ParseDeadline,
) -> Result<Vec<String>, ProviderError> {
    deadline.check()?;
    let sql_error = |error| deadline.sql_error(error);
    let declaration: Option<String> = conn
        .query_row(
            "SELECT sql FROM sqlite_schema WHERE type='table' AND name=?1 COLLATE BINARY",
            [name],
            |row| row.get(0),
        )
        .optional()
        .map_err(sql_error)?;
    let declaration = declaration.ok_or_else(|| invalid("required ordinary table missing"))?;
    if declaration.to_ascii_uppercase().contains("VIRTUAL TABLE") {
        return Err(invalid("virtual source tables are unsupported"));
    }
    let mut statement = conn
        .prepare("SELECT name FROM pragma_table_xinfo(?1) WHERE hidden=0")
        .map_err(sql_error)?;
    statement
        .query_map([name], |row| row.get(0))
        .map_err(sql_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(sql_error)
}
fn require_columns(
    conn: &Connection,
    name: &str,
    required: &[&str],
    deadline: ParseDeadline,
) -> Result<(), ProviderError> {
    deadline.check()?;
    let names = table_columns(conn, name, deadline)?;
    if required
        .iter()
        .any(|column| !names.iter().any(|name| name == column))
    {
        return Err(invalid("required source columns missing"));
    }
    Ok(())
}

fn open_snapshot(
    bytes: &[u8],
    deadline: ParseDeadline,
) -> Result<SnapshotConnection, ProviderError> {
    deadline.check()?;
    let sql_error = |error| deadline.sql_error(error);
    if bytes.len() as u64 > SQLITE_MAX_SOURCE_BYTES {
        return Err(ProviderError::SourceTooLarge {
            actual: bytes.len() as u64,
            max: SQLITE_MAX_SOURCE_BYTES,
        });
    }
    if !bytes.starts_with(SQLITE_MAGIC) || bytes.len() < 100 {
        return Err(invalid("not a complete SQLite snapshot"));
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
        return Err(invalid("invalid SQLite page bounds"));
    }
    // Input is the source layer's verified logical backup, never a raw main
    // file copied without its live WAL. Backup API snapshots can retain 2/2
    // header flags even though all committed pages are in the standalone image.
    // Normalize only the owned deserialization buffer; input stays byte-identical.
    // This transformation cannot establish that an arbitrary raw copy is fresh.
    if !matches!((bytes[18], bytes[19]), (1, 1) | (2, 2)) {
        return Err(invalid("invalid or mixed SQLite read/write version flags"));
    }
    let mut conn =
        SnapshotConnection::new(Connection::open_in_memory().map_err(sql_error)?, deadline);
    deadline.check()?;
    let decode_bytes = decode_buffer(bytes, deadline)?;
    conn.conn
        .deserialize("main", decode_bytes, true)
        .map_err(sql_error)?;
    deadline.check()?;
    conn.busy_timeout(std::time::Duration::ZERO)
        .map_err(sql_error)?;
    conn.set_limit(
        Limit::SQLITE_LIMIT_LENGTH,
        (STREAM_RECORD_MAX_BYTES * 2) as i32,
    )
    .map_err(sql_error)?;
    conn.set_limit(Limit::SQLITE_LIMIT_COLUMN, 128)
        .map_err(sql_error)?;
    conn.execute_batch("PRAGMA query_only=ON; PRAGMA trusted_schema=OFF; BEGIN DEFERRED;")
        .map_err(sql_error)?;
    let integrity: String = conn
        .query_row("PRAGMA quick_check(1)", [], |row| row.get(0))
        .map_err(sql_error)?;
    if integrity != "ok" {
        return Err(invalid("SQLite integrity check failed"));
    }
    require_columns(&conn, "steps", REQUIRED_STEP_COLUMNS, deadline)?;
    require_columns(
        &conn,
        "trajectory_meta",
        &["trajectory_id", "cascade_id", "trajectory_type", "source"],
        deadline,
    )?;
    deadline.check()?;
    Ok(conn)
}

fn native_uuid(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 36
        && bytes
            .iter()
            .any(|byte| byte.is_ascii_hexdigit() && *byte != b'0')
        && bytes.iter().enumerate().all(|(index, byte)| {
            if [8, 13, 18, 23].contains(&index) {
                *byte == b'-'
            } else {
                byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()
            }
        })
}

fn identity(conn: &Connection, deadline: ParseDeadline) -> Result<String, ProviderError> {
    deadline.check()?;
    let sql_error = |error| deadline.sql_error(error);
    let count: i64 = conn
        .query_row("SELECT count(*) FROM trajectory_meta", [], |row| row.get(0))
        .map_err(sql_error)?;
    if count != 1 {
        return Err(invalid("unique native trajectory identity required"));
    }
    let (trajectory, conversation, kind, source): (String, String, i64, i64) = conn
        .query_row(
            "SELECT trajectory_id,cascade_id,trajectory_type,source FROM trajectory_meta",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .map_err(sql_error)?;
    if !native_uuid(&trajectory)
        || !native_uuid(&conversation)
        || trajectory == conversation
        || kind != 4
        || source != 17
    {
        return Err(invalid(
            "native identity or CLI trajectory kind is unsupported",
        ));
    }
    let metadata_exists: Option<i64> = conn.query_row(
        "SELECT 1 FROM sqlite_schema WHERE type='table' AND name='trajectory_metadata_blob' COLLATE BINARY", [], |row| row.get(0),
    ).optional().map_err(sql_error)?;
    if metadata_exists.is_some() {
        require_columns(conn, "trajectory_metadata_blob", &["id", "data"], deadline)?;
        let mut statement = conn
            .prepare(
                "SELECT data FROM trajectory_metadata_blob WHERE id='main' COLLATE BINARY LIMIT 2",
            )
            .map_err(sql_error)?;
        let mut rows = statement.query([]).map_err(sql_error)?;
        if let Some(row) = rows.next().map_err(sql_error)? {
            let data = row.get_ref(0).map_err(sql_error)?;
            if let ValueRef::Blob(data) = data {
                let values = decode_fields_with_deadline(data, deadline)?;
                if string(&values, 6, deadline)?.is_some_and(|(value, _)| value != conversation) {
                    return Err(invalid("contradictory native conversation identity"));
                }
            } else if data != ValueRef::Null {
                return Err(invalid("trajectory metadata is not a protobuf blob"));
            }
            if rows.next().map_err(sql_error)?.is_some() {
                return Err(invalid("duplicate main trajectory metadata"));
            }
        }
    }
    deadline.check()?;
    Ok(conversation)
}

fn row_integer(
    row: &rusqlite::Row<'_>,
    column: usize,
    deadline: ParseDeadline,
) -> Result<i64, ProviderError> {
    deadline.check()?;
    let sql_error = |error| deadline.sql_error(error);
    match row.get_ref(column).map_err(sql_error)? {
        ValueRef::Integer(value) => Ok(value),
        _ => Err(invalid("stored step scalar has wrong type")),
    }
}

fn read_steps(
    conn: &Connection,
    result: &mut AntigravityObservation,
    mut sink: Option<&mut dyn CanonicalEventSink>,
    deadline: ParseDeadline,
) -> Result<(), ProviderError> {
    deadline.check()?;
    let sql_error = |error| deadline.sql_error(error);
    let count: i64 = conn
        .query_row("SELECT count(*) FROM steps", [], |row| row.get(0))
        .map_err(sql_error)?;
    if !(0..=MAX_STEPS as i64).contains(&count) {
        return Err(invalid("stored step count exceeds supported limit"));
    }
    let mut statement = conn.prepare(
        "SELECT idx,step_type,status,has_subtrajectory,step_format,step_payload FROM steps ORDER BY idx",
    ).map_err(sql_error)?;
    let mut rows = statement.query([]).map_err(sql_error)?;
    let mut expected = 0i64;
    loop {
        deadline.check()?;
        let next = rows.next().map_err(sql_error)?;
        deadline.check()?;
        let Some(row) = next else {
            break;
        };
        let index = row_integer(row, 0, deadline)?;
        let step_type = row_integer(row, 1, deadline)?;
        let status = row_integer(row, 2, deadline)?;
        let subtrajectory = row_integer(row, 3, deadline)?;
        let format = row_integer(row, 4, deadline)?;
        if index != expected || step_type < 0 || status < 0 || !matches!(subtrajectory, 0 | 1) {
            return Err(invalid(
                "invalid, duplicated or discontinuous stored step identity/scalars",
            ));
        }
        expected += 1;
        if format != 0 {
            result.incomplete(
                format!("step {index}: unsupported stored protobuf encoding"),
                true,
            );
            continue;
        }
        let ValueRef::Blob(payload) = row.get_ref(5).map_err(sql_error)? else {
            return Err(invalid("stored Step payload is not a protobuf blob"));
        };
        let step = decode_step_with_deadline(payload, deadline)?;
        if step.step_type != step_type as u64 || step.status != status as u64 {
            return Err(invalid("stored row and protobuf type/status disagree"));
        }
        if subtrajectory != 0 {
            result.incomplete(format!("step {index}: unsupported nested trajectory"), true);
            continue;
        }
        if let Some(ref mut sink) = sink {
            apply_step(
                result,
                &step,
                index as u64,
                None,
                Some(&mut **sink),
                deadline,
            )?;
        } else {
            apply_step(result, &step, index as u64, None, None, deadline)?;
        }
    }
    deadline.check()?;
    Ok(())
}

pub(crate) fn probe_conversation_snapshot(bytes: &[u8]) -> Result<ProbeResult, ProviderError> {
    let deadline = ParseDeadline::unlimited();
    let conn = open_snapshot(bytes, deadline)?;
    identity(&conn, deadline)?;
    Ok(ProbeResult {
        variant_id: CONVERSATION_VARIANT_ID.into(),
        confidence: Confidence::Confirmed,
        matched_evidence: vec![
            "standalone SQLite snapshot with Antigravity steps and a unique CLI cascade identity"
                .into(),
        ],
        unmatched_evidence: vec![
            "Step mapping is observed for CLI 1.1.16; other runtime versions remain unverified"
                .into(),
        ],
    })
}

pub(crate) fn parse_conversation_snapshot(
    bytes: &[u8],
    sink: &mut dyn CanonicalEventSink,
    deadline: ParseDeadline,
) -> Result<AntigravityObservation, ProviderError> {
    deadline.check()?;
    let conn = open_snapshot(bytes, deadline)?;
    let conversation = identity(&conn, deadline)?;
    // Validate all rows before the first event; later corrupt records cannot
    // leave an externally observed prefix. Both passes use the same immutable
    // in-memory, read-only snapshot and transaction.
    let mut validation = AntigravityObservation::new(AntigravitySourceFormat::ConversationSqlite);
    read_steps(&conn, &mut validation, None, deadline)?;
    let mut result = AntigravityObservation::new(AntigravitySourceFormat::ConversationSqlite);
    result.report.session_native_id = Some(conversation.clone());
    result.report.session_observation.provider_session_id =
        MetadataResolution::Resolved(conversation);
    read_steps(&conn, &mut result, Some(sink), deadline)?;
    result.diagnostic("SQLite message spans and unverified per-step timestamps are unavailable; loose encrypted protobuf envelopes are not supported".into());
    deadline.check()?;
    Ok(result)
}

#[cfg(test)]
mod deadline_tests {
    use super::*;
    use std::time::{Duration, Instant};

    #[test]
    fn native_sqlite_progress_interrupts_a_running_query_at_original_deadline() {
        let source = Connection::open_in_memory().unwrap();
        source.execute_batch(
            "CREATE TABLE steps(idx INTEGER,step_type INTEGER,status INTEGER,has_subtrajectory INTEGER,
             metadata BLOB,error_details BLOB,permissions BLOB,task_details BLOB,render_info BLOB,
             step_payload BLOB,step_format INTEGER);
             CREATE TABLE trajectory_meta(trajectory_id TEXT,cascade_id TEXT,trajectory_type INTEGER,source INTEGER);",
        ).unwrap();
        let bytes = source.serialize("main").unwrap().to_vec();
        let before = bytes.clone();
        let deadline = ParseDeadline::at(Instant::now() + Duration::from_millis(500));
        // Exercise the actual owned-copy/deserialization/schema path too: its
        // installed progress callback must survive sqlite3_deserialize.
        let db = open_snapshot(&bytes, deadline).unwrap();
        deadline.check().unwrap();
        // This statement cannot finish naturally within the deadline. There is
        // no Rust row loop, sleep, lowered fixture LIMIT or manually installed
        // test interrupt: only the production SQLite VM handler can stop it.
        let result = db.query_row(
            "WITH RECURSIVE counter(value) AS (SELECT 0 UNION ALL SELECT value+1 FROM counter WHERE value<1000000000) SELECT sum(value) FROM counter",
            [], |row| row.get::<_, i64>(0),
        );
        let error = result.unwrap_err();
        assert!(
            matches!(error, rusqlite::Error::SqliteFailure(code, _) if code.extended_code == rusqlite::ffi::SQLITE_INTERRUPT)
        );
        assert!(deadline.expired());
        assert_eq!(deadline.sql_error(error), ParseDeadline::exceeded());
        assert_eq!(bytes, before);
    }

    #[test]
    fn expired_sqlite_buffer_and_wire_decode_are_rejected_before_native_use() {
        let deadline = ParseDeadline::at(Instant::now() - Duration::from_secs(1));
        assert!(
            matches!(decode_buffer(&[], deadline), Err(error) if error == ParseDeadline::exceeded())
        );
        assert!(
            matches!(decode_fields_with_deadline(&[8, 1], deadline), Err(error) if error == ParseDeadline::exceeded())
        );
        assert!(
            matches!(decode_step_with_deadline(&[8, 14, 32, 3], deadline), Err(error) if error == ParseDeadline::exceeded())
        );
    }
}
