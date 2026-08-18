//! OpenCode provider adapter.
//!
//! Parses OpenCode's `opencode.db` SQLite format: session/message/part tables.
//! The adapter receives the SQLite file as a byte stream, writes it to a
//! temporary file, and opens it read-only (SQLITE_OPEN_READONLY + busy_timeout)
//! per PRD requirement #4.
//!
//! Format evidence: fast-resume (MIT) `src/adapters/opencode.rs`.
//! The schema queries are adapted from fast-resume under its MIT license.

use std::io::Write;

use agent_session_grep_ports::MetadataResolution;
use agent_session_grep_ports::{
    AdapterManifest, CanonicalEventSink, Confidence, MessageEvent, ParseReport, ProbeResult,
    ProviderAdapter, ProviderError, manifest_for,
};
use rusqlite::{Connection, OpenFlags};

/// Variant id surfaced in probe results.
const VARIANT_ID: &str = "opencode/sqlite-v1";

/// SQLite magic header: every SQLite database starts with "SQLite format 3\0".
const SQLITE_MAGIC: &[u8] = b"SQLite format 3\0";

/// OpenCode adapter: parses `opencode.db` (SQLite: session/message/part).
///
/// The adapter writes the byte stream to a temp file and opens it read-only.
/// This is necessary because rusqlite requires a file path (no in-memory
/// deserialize in 0.40). The temp file is cleaned up after parsing.
pub struct OpenCodeAdapter;

impl OpenCodeAdapter {
    pub fn new() -> Self {
        Self
    }
}

impl Default for OpenCodeAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl ProviderAdapter for OpenCodeAdapter {
    fn provider_id(&self) -> &str {
        "opencode"
    }

    fn manifest(&self) -> AdapterManifest {
        manifest_for(
            self.provider_id(),
            Some(1),
            &[
                "SQLite source has no byte spans; messages are attributed without source offsets",
                "only text parts with role user/assistant are committed; tool/other parts are ignored",
                "per-message timestamps are not extracted",
            ],
        )
    }

    fn probe(&self, bytes: &[u8]) -> Result<ProbeResult, ProviderError> {
        let mut matched = Vec::new();
        let mut unmatched = Vec::new();

        // Quick check: SQLite files start with a magic header.
        if bytes.len() < SQLITE_MAGIC.len() || &bytes[..SQLITE_MAGIC.len()] != SQLITE_MAGIC {
            return Err(ProviderError::AmbiguousVariant(
                "not a SQLite database (missing magic header)".into(),
            ));
        }

        matched.push("SQLite magic header detected".into());

        // Open read-only and check for OpenCode tables.
        // _temp_db drops after conn: the guard deletes the temp file once the
        // connection is closed (Windows cannot delete an open file).
        let (conn, _temp_db) = open_readonly_from_bytes(bytes)
            .map_err(|e| ProviderError::StructuralFatal(format!("failed to open SQLite: {e}")))?;

        // Check for OpenCode-specific tables: session, message, part.
        let has_session = table_exists(&conn, "session");
        let has_message = table_exists(&conn, "message");
        let has_part = table_exists(&conn, "part");

        if !has_session {
            return Err(ProviderError::AmbiguousVariant(
                "no `session` table found — not an OpenCode database".into(),
            ));
        }

        let confidence = if has_session && has_message && has_part {
            matched.push("OpenCode schema confirmed (session + message + part tables)".into());
            Confidence::Confirmed
        } else if has_session && has_message {
            matched.push("OpenCode schema (session + message tables, no part)".into());
            Confidence::High
        } else {
            matched.push("partial OpenCode schema (session table only)".into());
            unmatched.push("missing message/part tables".into());
            Confidence::Low
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
        let mut report = ParseReport::default();

        // _temp_db drops after conn (see probe): the temp file is deleted once
        // the connection is closed.
        let (conn, _temp_db) = open_readonly_from_bytes(bytes)
            .map_err(|e| ProviderError::StructuralFatal(format!("failed to open SQLite: {e}")))?;

        // Query messages with their session and role.
        // Schema (from fast-resume):
        //   session(id, title, directory, time_created, time_updated)
        //   message(id, session_id, data)  -- data is JSON with role
        //   part(id, message_id, data)     -- data is JSON with type/text

        // Collect session metadata.
        let mut session_meta: std::collections::HashMap<String, (Option<String>, Option<String>)> =
            std::collections::HashMap::new();
        if let Ok(mut stmt) = conn.prepare("SELECT id, title, directory FROM session")
            && let Ok(rows) = stmt.query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, Option<String>>(2)?,
                ))
            })
        {
            for row in rows.filter_map(Result::ok) {
                session_meta.insert(row.0, (row.1, row.2));
            }
        }

        // Collect text parts by message_id.
        let mut parts_by_message: std::collections::HashMap<String, Vec<String>> =
            std::collections::HashMap::new();
        if let Ok(mut stmt) = conn.prepare(
            "SELECT message_id, json_extract(data, '$.text') FROM part \
             WHERE json_extract(data, '$.type') = 'text' ORDER BY time_created ASC",
        ) && let Ok(rows) = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Option<String>>(1)?.unwrap_or_default(),
            ))
        }) {
            for (msg_id, text) in rows.filter_map(Result::ok) {
                if !text.is_empty() {
                    parts_by_message.entry(msg_id).or_default().push(text);
                }
            }
        }

        // Query messages ordered by time.
        let mut seq: u32 = 0;
        let mut session_ids: Vec<String> = Vec::new();

        if let Ok(mut stmt) = conn.prepare(
            "SELECT id, session_id, json_extract(data, '$.role') \
             FROM message ORDER BY time_created ASC",
        ) && let Ok(rows) = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?, // message id
                row.get::<_, String>(1)?, // session_id
                row.get::<_, String>(2)?, // role
            ))
        }) {
            for (msg_id, sess_id, role) in rows.filter_map(Result::ok) {
                if !matches!(role.as_str(), "user" | "assistant") {
                    continue;
                }
                let parts = parts_by_message.get(&msg_id);
                let text = match parts {
                    Some(parts) if !parts.is_empty() => parts.join("\n"),
                    _ => continue,
                };
                if text.trim().is_empty() {
                    continue;
                }

                // Session identity from first message.
                if report.session_native_id.is_none() {
                    report.session_native_id = Some(sess_id.clone());
                    report.session_observation.provider_session_id =
                        MetadataResolution::Resolved(sess_id.clone());
                    if let Some((_, cwd)) = session_meta.get(&sess_id)
                        && let Some(cwd) = cwd
                        && !cwd.trim().is_empty()
                    {
                        report.session_observation.original_working_directory =
                            MetadataResolution::Resolved(cwd.trim().to_string());
                        report.session_observation.pair_observed = true;
                    }
                }
                if !session_ids.iter().any(|s| s == &sess_id) {
                    session_ids.push(sess_id.clone());
                }

                sink.emit_message(MessageEvent {
                    seq,
                    native_id: &msg_id,
                    parent_native_id: None,
                    role: &role,
                    text: &text,
                    timestamp: None,
                    is_sidechain: false,
                    span: None, // SQLite doesn't have byte spans
                })
                .map_err(|e| ProviderError::StructuralFatal(e.to_string()))?;
                seq += 1;
                report.committed += 1;
            }
        }

        // Multi-session diagnostic.
        if session_ids.len() > 1 {
            report.session_observation.multi_session = true;
            report.session_observation.provider_session_id = MetadataResolution::Ambiguous;
            report.diagnostics.push(format!(
                "数据库包含 {} 个不同 session——单文件=单会话，全部消息归属首个会话 {}",
                session_ids.len(),
                session_ids[0]
            ));
        }

        Ok(report)
    }
}

/// Process-unique suffix for temp file names: pid + atomic counter.
///
/// Wall-clock nanoseconds alone can collide across parallel test threads when
/// the OS clock granularity is coarse (two `SystemTime::now()` calls within one
/// tick), and `File::create` would silently truncate the other thread's DB.
fn temp_file_suffix() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    format!(
        "{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    )
}

/// Deletes the temp SQLite file when dropped. Must be dropped AFTER the
/// `Connection` (Windows cannot delete an open file), so callers bind it in a
/// tuple pattern after the connection: `let (conn, _temp) = ...`.
struct TempDbGuard {
    path: std::path::PathBuf,
}

impl Drop for TempDbGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Open a SQLite database from bytes, read-only.
///
/// Writes bytes to a temp file, opens with SQLITE_OPEN_READONLY + busy_timeout,
/// and returns the connection plus a guard that deletes the temp file when the
/// connection has been dropped.
fn open_readonly_from_bytes(bytes: &[u8]) -> Result<(Connection, TempDbGuard), String> {
    let temp_dir = std::env::temp_dir();
    let temp_path = temp_dir.join(format!("asg-opencode-{}.db", temp_file_suffix()));
    let mut file = std::fs::File::create(&temp_path).map_err(|e| e.to_string())?;
    file.write_all(bytes).map_err(|e| e.to_string())?;
    file.sync_all().map_err(|e| e.to_string())?;
    drop(file);

    let conn = Connection::open_with_flags(
        &temp_path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|e| e.to_string())?;
    conn.busy_timeout(std::time::Duration::from_secs(1))
        .map_err(|e| e.to_string())?;

    Ok((conn, TempDbGuard { path: temp_path }))
}

/// Check if a table exists in the database.
fn table_exists(conn: &Connection, table_name: &str) -> bool {
    conn.prepare(&format!(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='{table_name}'"
    ))
    .and_then(|mut stmt| stmt.exists([]))
    .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_matches_provider_matrix() {
        let adapter = OpenCodeAdapter::new();
        let manifest = adapter.manifest();
        assert_eq!(manifest.provider_id, adapter.provider_id());
        assert_eq!(manifest.supported_variants, vec![VARIANT_ID.to_string()]);
        assert_eq!(manifest.capabilities.provider_id, adapter.provider_id());
        assert_eq!(manifest.capabilities.variant_id, VARIANT_ID);
        assert!(manifest.last_certified_targets.is_empty());
        assert_eq!(manifest.fixture_revision, Some(1));
    }

    #[test]
    fn probe_rejects_non_sqlite_bytes() {
        let adapter = OpenCodeAdapter::new();
        let result = adapter.probe(b"not a sqlite file");
        assert!(result.is_err());
    }

    #[test]
    fn probe_rejects_empty_bytes() {
        let adapter = OpenCodeAdapter::new();
        let result = adapter.probe(b"");
        assert!(result.is_err());
    }

    #[test]
    fn probe_confirms_opencode_database() {
        let adapter = OpenCodeAdapter::new();
        let db_bytes = create_test_opencode_db();
        let result = adapter.probe(&db_bytes).unwrap();
        assert_eq!(result.variant_id, VARIANT_ID);
        assert_eq!(result.confidence, Confidence::Confirmed);
    }

    #[test]
    fn parse_extracts_messages_from_opencode_db() {
        let adapter = OpenCodeAdapter::new();
        let db_bytes = create_test_opencode_db();

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

        let mut sink = CountSink { count: 0 };
        let report = adapter.parse(&db_bytes, &mut sink).unwrap();
        assert_eq!(report.committed, 2);
        assert!(report.session_native_id.is_some());
    }

    /// Create a test OpenCode SQLite database in memory and return its bytes.
    fn create_test_opencode_db() -> Vec<u8> {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE session (id TEXT PRIMARY KEY, title TEXT, directory TEXT, time_created INTEGER, time_updated INTEGER);
             CREATE TABLE message (id TEXT PRIMARY KEY, session_id TEXT, data TEXT, time_created INTEGER);
             CREATE TABLE part (id TEXT PRIMARY KEY, message_id TEXT, data TEXT, time_created INTEGER);
             INSERT INTO session VALUES ('ses_1', 'test', '/work', 1, 2);
             INSERT INTO message VALUES ('msg_1', 'ses_1', '{\"role\":\"user\"}', 1);
             INSERT INTO message VALUES ('msg_2', 'ses_1', '{\"role\":\"assistant\"}', 2);
             INSERT INTO part VALUES ('part_1', 'msg_1', '{\"type\":\"text\",\"text\":\"hello world\"}', 1);
             INSERT INTO part VALUES ('part_2', 'msg_2', '{\"type\":\"text\",\"text\":\"hi there\"}', 2);",
        )
        .unwrap();

        // Serialize the in-memory DB to bytes via backup.
        let temp_path = std::env::temp_dir().join(format!("asg-test-{}.db", temp_file_suffix()));
        conn.execute_batch(&format!("VACUUM INTO '{}'", temp_path.display()))
            .unwrap();
        drop(conn);
        let bytes = std::fs::read(&temp_path).unwrap();
        let _ = std::fs::remove_file(&temp_path);
        bytes
    }
}
