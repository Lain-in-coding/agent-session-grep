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

        // Open read-only and check for OpenCode tables. `db` unlinks the temp
        // copy when it goes out of scope (see `TempDb`).
        let db = open_readonly_from_bytes(bytes)
            .map_err(|e| ProviderError::StructuralFatal(format!("failed to open SQLite: {e}")))?;
        let conn = &db.conn;

        // Check for OpenCode-specific tables: session, message, part.
        let has_session = table_exists(conn, "session")?;
        let has_message = table_exists(conn, "message")?;
        let has_part = table_exists(conn, "part")?;

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

        // `db` unlinks the temp copy when it goes out of scope (see `TempDb`).
        let db = open_readonly_from_bytes(bytes)
            .map_err(|e| ProviderError::StructuralFatal(format!("failed to open SQLite: {e}")))?;
        let conn = &db.conn;

        // Query messages with their session and role.
        // Schema (from fast-resume):
        //   session(id, title, directory, time_created, time_updated)
        //   message(id, session_id, data)  -- data is JSON with role
        //   part(id, message_id, data)     -- data is JSON with type/text

        let sql_error = |error: rusqlite::Error| {
            ProviderError::StructuralFatal(format!("OpenCode SQLite query failed: {error}"))
        };
        let mut session_meta = std::collections::BTreeMap::new();
        let mut stmt = conn
            .prepare("SELECT id, directory FROM session ORDER BY id")
            .map_err(sql_error)?;
        let rows = stmt
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?))
            })
            .map_err(sql_error)?;
        for row in rows {
            let (id, directory) = row.map_err(sql_error)?;
            if id.trim().is_empty() {
                return Err(ProviderError::StructuralFatal(
                    "OpenCode session id is empty".into(),
                ));
            }
            let cwd = directory.filter(|value| !value.trim().is_empty());
            session_meta.insert(
                id.clone(),
                agent_session_grep_ports::ProviderSessionIdentity {
                    source_key: id.clone(),
                    observation: agent_session_grep_ports::ProviderSessionObservation {
                        provider_session_id: MetadataResolution::Resolved(id),
                        original_working_directory: cwd
                            .clone()
                            .map(MetadataResolution::Resolved)
                            .unwrap_or_default(),
                        pair_observed: cwd.is_some(),
                        multi_session: false,
                    },
                },
            );
        }

        let mut parts_by_message: std::collections::HashMap<String, Vec<String>> =
            std::collections::HashMap::new();
        let mut stmt = conn
            .prepare(
                "SELECT message_id, json_extract(data, '$.text') FROM part \
             WHERE json_extract(data, '$.type') = 'text' ORDER BY time_created ASC, id ASC",
            )
            .map_err(sql_error)?;
        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Option<String>>(1)?.unwrap_or_default(),
                ))
            })
            .map_err(sql_error)?;
        for row in rows {
            let (msg_id, text) = row.map_err(sql_error)?;
            if !text.is_empty() {
                parts_by_message.entry(msg_id).or_default().push(text);
            }
        }

        let mut seq: u32 = 0;
        let mut session_ids = std::collections::BTreeSet::new();
        let mut stmt = conn
            .prepare(
                "SELECT id, session_id, json_extract(data, '$.role') \
             FROM message ORDER BY time_created ASC, id ASC",
            )
            .map_err(sql_error)?;
        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, rusqlite::types::Value>(2)?,
                ))
            })
            .map_err(sql_error)?;
        for row in rows {
            let (msg_id, sess_id, role) = row.map_err(sql_error)?;
            // A decoded SQL value lacking a textual role is a malformed
            // provider record, counted as skipped. Prepare/query/row-decoding
            // failures above remain fatal; no backend error is swallowed.
            let rusqlite::types::Value::Text(role) = role else {
                report.skipped += 1;
                report
                    .diagnostics
                    .push("OpenCode message has no textual role; skipped".into());
                continue;
            };
            if !matches!(role.as_str(), "user" | "assistant") {
                continue;
            }
            let text = match parts_by_message.get(&msg_id) {
                Some(parts) => parts.join("\n"),
                None => continue,
            };
            if text.trim().is_empty() {
                continue;
            }
            let session = session_meta.get(&sess_id).ok_or_else(|| {
                ProviderError::StructuralFatal(
                    "OpenCode message references an unknown session".into(),
                )
            })?;
            if report.session_native_id.is_none() {
                report.session_native_id = Some(sess_id.clone());
                report.session_observation = session.observation.clone();
            }
            session_ids.insert(sess_id);
            sink.emit_message(MessageEvent {
                session: Some(session),
                seq,
                native_id: &msg_id,
                parent_native_id: None,
                role: &role,
                text: &text,
                timestamp: None,
                is_sidechain: false,
                span: None,
            })
            .map_err(|e| ProviderError::StructuralFatal(e.to_string()))?;
            seq = seq.checked_add(1).ok_or_else(|| {
                ProviderError::StructuralFatal("too many OpenCode messages".into())
            })?;
            report.committed += 1;
        }
        if session_ids.len() > 1 {
            report.session_observation.multi_session = true;
            report.session_observation.provider_session_id = MetadataResolution::Ambiguous;
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

/// Deletes the owned temp SQLite database and sidecars after its connection closes.
/// A final read-only connection may leave WAL/SHM files behind.
struct TempDbGuard {
    path: std::path::PathBuf,
}

impl Drop for TempDbGuard {
    fn drop(&mut self) {
        for suffix in ["", "-wal", "-shm"] {
            let mut owned_file = self.path.as_os_str().to_os_string();
            owned_file.push(suffix);
            let _ = std::fs::remove_file(std::path::Path::new(&owned_file));
        }
    }
}

/// A read-only connection over a temp copy of the source bytes, bundled with the
/// guard that unlinks that copy.
///
/// **Field order is load-bearing.** Struct fields drop in declaration order, so
/// `conn` closes the database before `_guard` unlinks the file. Windows refuses
/// to delete a file that is still open and `remove_file`'s error is discarded, so
/// the reverse order leaks every temp copy silently. A tuple binding
/// (`let (conn, guard) = ...`) drops the *later* binding first — i.e. the guard
/// while the connection is still open — which is exactly the broken order this
/// struct exists to prevent.
struct TempDb {
    conn: Connection,
    _guard: TempDbGuard,
}

impl TempDb {
    /// Path of the temp copy backing this connection.
    #[cfg(test)]
    fn temp_path(&self) -> &std::path::Path {
        &self._guard.path
    }
}

/// Open a SQLite database from bytes, read-only.
///
/// Writes bytes to a temp file, opens with SQLITE_OPEN_READONLY + busy_timeout,
/// and returns a [`TempDb`] that deletes the temp copy once it goes out of scope.
fn open_readonly_from_bytes(bytes: &[u8]) -> Result<TempDb, String> {
    let temp_dir = std::env::temp_dir();
    let temp_path = temp_dir.join(format!("asg-opencode-{}.db", temp_file_suffix()));
    let guard = TempDbGuard { path: temp_path };
    let mut file = std::fs::File::create(&guard.path).map_err(|e| e.to_string())?;
    file.write_all(bytes).map_err(|e| e.to_string())?;
    file.sync_all().map_err(|e| e.to_string())?;
    drop(file);

    let conn = Connection::open_with_flags(
        &guard.path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|e| e.to_string())?;
    conn.busy_timeout(std::time::Duration::from_secs(1))
        .map_err(|e| e.to_string())?;

    Ok(TempDb {
        conn,
        _guard: guard,
    })
}

/// Check if a table exists in the database.
fn table_exists(conn: &Connection, table_name: &str) -> Result<bool, ProviderError> {
    conn.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name=?1")
        .and_then(|mut stmt| stmt.exists([table_name]))
        .map_err(|error| {
            ProviderError::StructuralFatal(format!("OpenCode SQLite schema query failed: {error}"))
        })
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

    fn assert_wal_temp_copy_cleanup(query: &str, should_fail: bool) {
        let fixture = TempDbGuard {
            path: std::env::temp_dir().join(format!(
                "asg-opencode-wal-fixture-{}.db",
                temp_file_suffix()
            )),
        };
        let writer = Connection::open(&fixture.path).unwrap();
        writer
            .execute_batch(
                "PRAGMA journal_mode=WAL;
                 CREATE TABLE cleanup_fixture (value INTEGER);
                 INSERT INTO cleanup_fixture VALUES (7);",
            )
            .unwrap();
        drop(writer);
        let bytes = std::fs::read(&fixture.path).unwrap();
        let mut copy_path = None;
        let result = (|| -> rusqlite::Result<i64> {
            let db = open_readonly_from_bytes(&bytes).unwrap();
            let path = db.temp_path().to_path_buf();
            // A real read materializes the private WAL/SHM files.
            db.conn
                .query_row("SELECT value FROM cleanup_fixture", [], |row| {
                    row.get::<_, i64>(0)
                })?;
            for suffix in ["-wal", "-shm"] {
                let mut sidecar = path.as_os_str().to_os_string();
                sidecar.push(suffix);
                assert!(std::path::Path::new(&sidecar).exists());
            }
            copy_path = Some(path);
            // The error case returns while TempDb is still a local owner.
            db.conn.query_row(query, [], |row| row.get(0))
        })();
        assert_eq!(result.is_err(), should_fail);
        let path = copy_path.unwrap();
        let mut remaining = Vec::new();
        for suffix in ["", "-wal", "-shm"] {
            let mut owned_file = path.as_os_str().to_os_string();
            owned_file.push(suffix);
            let owned_file = std::path::Path::new(&owned_file);
            if owned_file.exists() {
                remaining.push(suffix);
                // Do not leave this test's files behind when the assertion fails.
                std::fs::remove_file(owned_file).unwrap();
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
    fn temp_copy_is_unlinked_once_the_connection_goes_out_of_scope() {
        // Regression: the guard used to be returned next to the connection in a
        // tuple, and a tuple binding drops the *later* binding first — so the
        // unlink ran while SQLite still held the file open. Windows refuses that
        // delete and `remove_file`'s error is discarded, so every parse silently
        // leaked its temp copy. `TempDb`'s field order fixes the sequence; this
        // test fails if the pairing is ever unbundled again.
        let db_bytes = create_test_opencode_db();
        let leaked_path = {
            let db = open_readonly_from_bytes(&db_bytes).unwrap();
            let path = db.temp_path().to_path_buf();
            assert!(path.exists(), "temp copy must exist while the db is open");
            path
        };
        assert!(
            !leaked_path.exists(),
            "temp copy must be unlinked after the connection is dropped"
        );
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

    #[test]
    fn parse_passes_noise_shaped_user_text_through_verbatim() {
        // 钉住测试：OpenCode SQLite 没有 system-reminder / AGENTS.md /
        // 环境上下文等注入概念（message/part 的 text 就是消息原文；part 查询
        // 只按 `type='text'` 过滤块类型，不检查文本形状）。形似噪声的文本必须
        // 逐字透传，防止将来把别家格式的过滤规则盲目搬来造成 silent drift。
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE session (id TEXT PRIMARY KEY, title TEXT, directory TEXT, time_created INTEGER, time_updated INTEGER);
             CREATE TABLE message (id TEXT PRIMARY KEY, session_id TEXT, data TEXT, time_created INTEGER);
             CREATE TABLE part (id TEXT PRIMARY KEY, message_id TEXT, data TEXT, time_created INTEGER);
             INSERT INTO session VALUES ('ses_1', 'test', '/work', 1, 2);
             INSERT INTO message VALUES ('msg_1', 'ses_1', '{\"role\":\"user\"}', 1);
             INSERT INTO message VALUES ('msg_2', 'ses_1', '{\"role\":\"user\"}', 2);
             INSERT INTO part VALUES ('part_1', 'msg_1', '{\"type\":\"text\",\"text\":\"<system-reminder>reminder text</system-reminder>\"}', 1);
             INSERT INTO part VALUES ('part_2', 'msg_2', '{\"type\":\"text\",\"text\":\"# AGENTS.md instructions\"}', 2);",
        )
        .unwrap();
        let temp_path = std::env::temp_dir().join(format!("asg-test-{}.db", temp_file_suffix()));
        conn.execute_batch(&format!("VACUUM INTO '{}'", temp_path.display()))
            .unwrap();
        drop(conn);
        let db_bytes = std::fs::read(&temp_path).unwrap();
        let _ = std::fs::remove_file(&temp_path);

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

        let adapter = OpenCodeAdapter::new();
        let mut sink = TextSink { texts: Vec::new() };
        let report = adapter.parse(&db_bytes, &mut sink).unwrap();
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
