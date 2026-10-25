//! Dependency-preserving retention of disposable managed runtime history.
//!
//! The caller owns the catalog writer lease, a BEGIN IMMEDIATE transaction,
//! and the same root's exclusive HistoryReaders guard. Capture COMPLETE control
//! and validated cache dependencies while that guard is held. Busy, unknown or
//! missing dependencies must skip GC; an empty list is not a fallback.
//!
//! This module never opens a database, commits the outer transaction, changes
//! content/policy/generation, or deletes source evidence. Receipt/discovery tails
//! are diagnostic retention, not observation freshness or liveness. Control GC
//! must merge its freshly verified dependencies with every returned catalog
//! token, including old boots, and skip GC for PendingCatalogPrune.

use crate::{SCHEMA_VERSION, managed_discovery, managed_receipt, managed_store};
use agent_session_grep_ports::{
    PortError, PortResult,
    control::{ControlId, CycleSeq, ObservationToken},
    managed::{DiscoverySource, ReadSnapshot, RevisionId, RevisionRef, SourceId},
};
use rusqlite::{Connection, OptionalExtension, Row, params};
use std::{collections::BTreeMap, fmt, time::Instant};

const MAX_BATCH_ROWS: usize = 256;
const MAX_BOUND: usize = 65_536;

fn invalid() -> PortError {
    PortError::InvalidRequest("invalid managed history retention request".into())
}
fn corrupt() -> PortError {
    PortError::SchemaIncompatible("managed history dependencies are unavailable or invalid".into())
}
fn busy() -> PortError {
    PortError::WriterBusy("managed history retention is busy or exceeded its bounds".into())
}
fn stale() -> PortError {
    PortError::GenerationMismatch("managed history snapshot changed".into())
}
fn sql(error: rusqlite::Error) -> PortError {
    match error.sqlite_error_code() {
        Some(
            rusqlite::ErrorCode::DatabaseBusy
            | rusqlite::ErrorCode::DatabaseLocked
            | rusqlite::ErrorCode::OperationInterrupted,
        ) => busy(),
        _ => corrupt(),
    }
}
fn time(deadline: Instant) -> PortResult<()> {
    if Instant::now() >= deadline {
        Err(busy())
    } else {
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HistoryLimits {
    pub receipt_tail_per_source: usize,
    pub discovery_tail_per_selection: usize,
    /// Maximum receipt/discovery parent records removed in this transaction.
    /// Their verified claim/source rows are removed in the same savepoint.
    pub batch_rows: usize,
    pub max_dependencies: usize,
    pub max_cycle_tokens: usize,
}
impl Default for HistoryLimits {
    fn default() -> Self {
        Self {
            receipt_tail_per_source: 2,
            discovery_tail_per_selection: 1,
            batch_rows: 64,
            max_dependencies: 16_384,
            max_cycle_tokens: 16_384,
        }
    }
}
impl HistoryLimits {
    fn validate(self) -> PortResult<()> {
        // Keep at least the highest source revision sequence so allocation by
        // MAX(revision_seq)+1 never reuses an expired observation sequence.
        if !(1..=64).contains(&self.receipt_tail_per_source)
            || !(1..=64).contains(&self.discovery_tail_per_selection)
            || !(1..=MAX_BATCH_ROWS).contains(&self.batch_rows)
            || !(1..=MAX_BOUND).contains(&self.max_dependencies)
            || !(1..=MAX_BOUND).contains(&self.max_cycle_tokens)
        {
            return Err(invalid());
        }
        Ok(())
    }
}

/// Complete, root-verified caller inventory. No Default: omission or failed
/// capture must not silently mean that control/cache has no dependencies.
#[derive(Clone, PartialEq, Eq)]
pub struct HistoryDependencies {
    pub installation_id: ControlId,
    pub snapshot: ReadSnapshot,
    /// Pending/recent barriers, source_updates receipt/last-observed cycles,
    /// missing/rewrite first+confirm cycles, and any retained job dependencies.
    pub keep_cycles: Vec<CycleSeq>,
    /// Exact control receipt IDs, including receipts from an older worker boot.
    pub keep_receipts: Vec<RevisionId>,
}
impl fmt::Debug for HistoryDependencies {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("HistoryDependencies([private])")
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HistoryCounts {
    pub receipts_deleted: u64,
    pub receipt_claims_deleted: u64,
    pub retained_proofs_deleted: u64,
    pub discoveries_deleted: u64,
    pub discovery_sources_deleted: u64,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CycleRetention {
    /// Every surviving catalog receipt/discovery token, without truncation.
    /// The caller must also retain its current control-only dependencies.
    Complete(Vec<ObservationToken>),
    /// Too many surviving tokens to hand back a complete bounded inventory.
    /// This catalog batch is valid, but the caller MUST skip control pruning.
    PendingCatalogPrune,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryPrune {
    pub counts: HistoryCounts,
    pub has_more: bool,
    pub cycles: CycleRetention,
}

/// Remove one small batch under a caller-owned write transaction. All catalog
/// deletes are inside a savepoint and roll back on any error, even if the
/// caller subsequently commits its outer transaction. A failing rollback is
/// still an error; the caller must discard/roll back its connection then.
///
/// The dedicated GC connection's progress handler uses the SAME deadline and
/// is cleared before returning. No snapshot/lease/SQLite handle survives this
/// call. Cache revision IDs must come from fully validated, same-root sets.
pub fn prune_in_tx(
    conn: &Connection,
    dependencies: &HistoryDependencies,
    cache_revisions: &[RevisionId],
    limits: HistoryLimits,
    deadline: Instant,
) -> PortResult<HistoryPrune> {
    time(deadline)?;
    limits.validate()?;
    let input_count = dependencies
        .keep_cycles
        .len()
        .checked_add(dependencies.keep_receipts.len())
        .and_then(|count| count.checked_add(cache_revisions.len()))
        .ok_or_else(invalid)?;
    if input_count > limits.max_dependencies {
        return Err(busy());
    }
    if conn.is_autocommit()
        || !conn
            .pragma_query_value(None, "foreign_keys", |r| r.get::<_, bool>(0))
            .map_err(sql)?
        || conn
            .pragma_query_value(None, "query_only", |r| r.get::<_, bool>(0))
            .map_err(sql)?
    {
        return Err(invalid());
    }
    conn.busy_handler(Some(|_| false)).map_err(sql)?;
    conn.progress_handler(1000, Some(move || Instant::now() >= deadline))
        .map_err(sql)?;
    if let Err(error) = conn.execute_batch("SAVEPOINT asg_history_prune;") {
        conn.progress_handler(0, None::<fn() -> bool>)
            .map_err(sql)?;
        return Err(sql(error));
    }
    let mut result = prune_inner(conn, dependencies, cache_revisions, limits, deadline);
    if let Err(error) = conn.progress_handler(0, None::<fn() -> bool>) {
        result = Err(sql(error));
    }
    if result.is_ok()
        && let Err(error) = time(deadline)
    {
        result = Err(error);
    }
    match result {
        Ok(pruned) => {
            if let Err(error) = conn.execute_batch("RELEASE asg_history_prune;") {
                rollback(conn)?;
                return Err(sql(error));
            }
            Ok(pruned)
        }
        Err(error) => {
            rollback(conn)?;
            Err(error)
        }
    }
}
fn rollback(conn: &Connection) -> PortResult<()> {
    conn.execute_batch("ROLLBACK TO asg_history_prune; RELEASE asg_history_prune;")
        .map_err(sql)
}

const TEMP_SCHEMA: &str = "
CREATE TEMP TABLE history_control_cycles(cycle_seq INTEGER PRIMARY KEY) WITHOUT ROWID;
CREATE TEMP TABLE history_keep_receipts(revision_id TEXT PRIMARY KEY) WITHOUT ROWID;
CREATE TEMP TABLE history_keep_discoveries(cycle_seq INTEGER NOT NULL,selection_id TEXT NOT NULL,PRIMARY KEY(cycle_seq,selection_id)) WITHOUT ROWID;
CREATE TEMP TABLE history_delete_discoveries(cycle_seq INTEGER NOT NULL,selection_id TEXT NOT NULL,PRIMARY KEY(cycle_seq,selection_id)) WITHOUT ROWID;
CREATE TEMP TABLE history_delete_receipts(revision_id TEXT PRIMARY KEY) WITHOUT ROWID;
";
const CLEAN_TEMP: &str = "
DROP TABLE temp.history_control_cycles;
DROP TABLE temp.history_keep_receipts;
DROP TABLE temp.history_keep_discoveries;
DROP TABLE temp.history_delete_discoveries;
DROP TABLE temp.history_delete_receipts;
";

fn prune_inner(
    conn: &Connection,
    dependencies: &HistoryDependencies,
    cache_revisions: &[RevisionId],
    limits: HistoryLimits,
    deadline: Instant,
) -> PortResult<HistoryPrune> {
    verify_snapshot(conn, dependencies)?;
    verify_structure(conn, &dependencies.snapshot)?;
    time(deadline)?;
    conn.execute_batch(TEMP_SCHEMA).map_err(sql)?;
    for cycle in &dependencies.keep_cycles {
        time(deadline)?;
        conn.execute(
            "INSERT OR IGNORE INTO history_control_cycles VALUES(?1)",
            [cycle.get()],
        )
        .map_err(sql)?;
    }
    for revision in dependencies.keep_receipts.iter().chain(cache_revisions) {
        time(deadline)?;
        managed_receipt::read_checked(conn, revision.as_str(), None)?;
        conn.execute(
            "INSERT OR IGNORE INTO history_keep_receipts VALUES(?1)",
            [revision.as_str()],
        )
        .map_err(sql)?;
    }
    // A later incomplete discovery is a superseder too. Never select by
    // complete=1, heartbeat, wall time, or current boot/incarnation only.
    conn.execute(
        "INSERT OR IGNORE INTO history_keep_discoveries SELECT cycle_seq,selection_id FROM (SELECT cycle_seq,selection_id,ROW_NUMBER() OVER(PARTITION BY selection_id ORDER BY cycle_seq DESC) AS ordinal FROM discovery_receipts) WHERE ordinal<=?1",
        [limits.discovery_tail_per_selection as i64],
    ).map_err(sql)?;
    conn.execute_batch("INSERT OR IGNORE INTO history_keep_discoveries SELECT d.cycle_seq,d.selection_id FROM discovery_receipts d JOIN history_control_cycles c USING(cycle_seq);").map_err(sql)?;
    if count(conn, "SELECT COUNT(*) FROM history_keep_discoveries")?
        > limits.max_dependencies as u64
    {
        return Err(busy());
    }
    conn.execute(
        "INSERT INTO history_delete_discoveries SELECT d.cycle_seq,d.selection_id FROM discovery_receipts d LEFT JOIN history_keep_discoveries k USING(cycle_seq,selection_id) WHERE k.cycle_seq IS NULL ORDER BY d.cycle_seq,d.selection_id LIMIT ?1",
        [limits.batch_rows as i64],
    ).map_err(sql)?;
    verify_discoveries(conn, limits.max_dependencies, deadline)?;
    // Source heads and every evidence table may point at DIFFERENT historical
    // receipts. Head freshness cannot substitute for those original proofs.
    conn.execute_batch("INSERT OR IGNORE INTO history_keep_receipts SELECT visible_revision_id FROM source_heads WHERE visible_revision_id IS NOT NULL UNION SELECT latest_receipt_id FROM source_heads WHERE latest_receipt_id IS NOT NULL UNION SELECT last_attempt_id FROM source_heads WHERE last_attempt_id IS NOT NULL UNION SELECT revision_id FROM source_projections UNION SELECT revision_id FROM source_occurrences UNION SELECT revision_id FROM source_entity_projections UNION SELECT revision_id FROM source_session_projections;").map_err(sql)?;
    conn.execute(
        "INSERT OR IGNORE INTO history_keep_receipts SELECT revision_id FROM (SELECT revision_id,ROW_NUMBER() OVER(PARTITION BY source_id ORDER BY revision_seq DESC) AS ordinal FROM source_revision_receipts) WHERE ordinal<=?1",
        [limits.receipt_tail_per_source as i64],
    ).map_err(sql)?;
    conn.execute_batch("INSERT OR IGNORE INTO history_keep_receipts SELECT r.revision_id FROM source_revision_receipts r JOIN history_control_cycles c USING(cycle_seq);").map_err(sql)?;
    retain_source_context(conn, limits.max_dependencies, deadline)?;
    close_content_revisions(conn)?;
    verify_live_receipts(conn, limits.max_dependencies, deadline)?;
    // Unexpired obsolete discoveries left by this batch still depend on their
    // exact revisions. Keep those in SQLite, without an unbounded Rust vector.
    conn.execute_batch("INSERT OR IGNORE INTO history_keep_receipts SELECT s.revision_id FROM discovery_sources s LEFT JOIN history_delete_discoveries d USING(cycle_seq,selection_id) WHERE d.cycle_seq IS NULL;").map_err(sql)?;
    retain_source_context(conn, limits.max_dependencies, deadline)?;
    close_content_revisions(conn)?;
    let discovery_sources_deleted = conn.execute("DELETE FROM discovery_sources WHERE (cycle_seq,selection_id) IN(SELECT cycle_seq,selection_id FROM history_delete_discoveries)", []).map_err(sql)? as u64;
    let discoveries_deleted = conn.execute("DELETE FROM discovery_receipts WHERE (cycle_seq,selection_id) IN(SELECT cycle_seq,selection_id FROM history_delete_discoveries)", []).map_err(sql)? as u64;
    let mut counts = HistoryCounts {
        discovery_sources_deleted,
        discoveries_deleted,
        ..HistoryCounts::default()
    };
    let remaining = limits.batch_rows - counts.discoveries_deleted as usize;
    conn.execute(
        "INSERT INTO history_delete_receipts SELECT r.revision_id FROM source_revision_receipts r LEFT JOIN history_keep_receipts k USING(revision_id) WHERE k.revision_id IS NULL AND NOT EXISTS(SELECT 1 FROM source_revision_receipts child WHERE child.content_revision_id=r.revision_id AND child.revision_id!=r.revision_id) ORDER BY r.revision_seq DESC,r.revision_id LIMIT ?1",
        [remaining as i64],
    ).map_err(sql)?;
    verify_delete_receipts(conn, deadline)?;
    counts.receipt_claims_deleted = conn.execute("DELETE FROM receipt_selection_claims WHERE revision_id IN(SELECT revision_id FROM history_delete_receipts)", []).map_err(sql)? as u64;
    counts.retained_proofs_deleted = conn.execute("DELETE FROM retained_source_receipts WHERE revision_id IN(SELECT revision_id FROM history_delete_receipts)", []).map_err(sql)? as u64;
    counts.receipts_deleted = conn.execute("DELETE FROM source_revision_receipts WHERE revision_id IN(SELECT revision_id FROM history_delete_receipts)", []).map_err(sql)? as u64;
    let has_more: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM discovery_receipts d LEFT JOIN history_keep_discoveries k USING(cycle_seq,selection_id) WHERE k.cycle_seq IS NULL) OR EXISTS(SELECT 1 FROM source_revision_receipts r LEFT JOIN history_keep_receipts k USING(revision_id) WHERE k.revision_id IS NULL AND NOT EXISTS(SELECT 1 FROM source_revision_receipts child WHERE child.content_revision_id=r.revision_id AND child.revision_id!=r.revision_id))",
        [], |row| row.get(0),
    ).map_err(sql)?;
    let cycles = retained_tokens(conn, limits.max_cycle_tokens, deadline)?;
    time(deadline)?;
    conn.execute_batch(CLEAN_TEMP).map_err(sql)?;
    Ok(HistoryPrune {
        counts,
        has_more,
        cycles,
    })
}

fn retain_source_context(conn: &Connection, max: usize, deadline: Instant) -> PortResult<()> {
    for revision in crate::managed_source_context::history_roots(conn, max, deadline)? {
        conn.execute(
            "INSERT OR IGNORE INTO history_keep_receipts VALUES(?1)",
            [revision.as_str()],
        )
        .map_err(sql)?;
    }
    let mut statement = conn
        .prepare("SELECT revision_id FROM history_keep_receipts LIMIT ?1")
        .map_err(sql)?;
    let mut rows = statement.query([max as i64 + 1]).map_err(sql)?;
    let mut seeds = Vec::new();
    while let Some(row) = rows.next().map_err(sql)? {
        if seeds.len() >= max {
            return Err(busy());
        }
        seeds.push(
            RevisionId::parse(&row.get::<_, String>(0).map_err(sql)?).map_err(|_| corrupt())?,
        );
    }
    drop(rows);
    drop(statement);
    for revision in crate::managed_source_context::dependency_closure(conn, &seeds, max, deadline)?
    {
        conn.execute(
            "INSERT OR IGNORE INTO history_keep_receipts VALUES(?1)",
            [revision.as_str()],
        )
        .map_err(sql)?;
    }
    Ok(())
}

fn count(conn: &Connection, query: &str) -> PortResult<u64> {
    let value: i64 = conn.query_row(query, [], |row| row.get(0)).map_err(sql)?;
    u64::try_from(value).map_err(|_| corrupt())
}
fn verify_snapshot(conn: &Connection, dependencies: &HistoryDependencies) -> PortResult<()> {
    ControlId::parse(&dependencies.snapshot.catalog_incarnation).map_err(|_| invalid())?;
    if dependencies.snapshot.generation < 0
        || dependencies.snapshot.destructive_epoch < 0
        || dependencies.snapshot.policy_epoch < 0
    {
        return Err(invalid());
    }
    let version: i64 = conn
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(sql)?;
    let app: i64 = conn
        .pragma_query_value(None, "application_id", |row| row.get(0))
        .map_err(sql)?;
    if version != SCHEMA_VERSION || app != managed_store::APPLICATION_ID {
        return Err(corrupt());
    }
    let (installation, incarnation, generation, epoch): (String, String, i64, i64) = conn.query_row(
        "SELECT installation_id,catalog_incarnation,active_generation,destructive_epoch FROM catalog_meta CROSS JOIN store_metadata WHERE catalog_meta.singleton=1 AND store_metadata.singleton=1 AND managed_mode=1 AND projection_contract_version=1",
        [], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?)),
    ).map_err(sql)?;
    ControlId::parse(&installation).map_err(|_| corrupt())?;
    ControlId::parse(&incarnation).map_err(|_| corrupt())?;
    if generation < 0 || epoch < 0 {
        return Err(corrupt());
    }
    if installation != dependencies.installation_id.as_str()
        || incarnation != dependencies.snapshot.catalog_incarnation
        || generation != dependencies.snapshot.generation
        || epoch != dependencies.snapshot.destructive_epoch
    {
        return Err(stale());
    }
    Ok(())
}
fn exists(conn: &Connection, query: &str) -> PortResult<bool> {
    conn.query_row(query, [], |row| row.get(0)).map_err(sql)
}

fn verify_structure(conn: &Connection, snapshot: &ReadSnapshot) -> PortResult<()> {
    let mut statement = conn.prepare("PRAGMA foreign_key_check").map_err(sql)?;
    if statement
        .query([])
        .map_err(sql)?
        .next()
        .map_err(sql)?
        .is_some()
    {
        return Err(corrupt());
    }
    drop(statement);
    // Set-oriented checks prevent deleting a malformed obsolete row to hide
    // corruption. Original payloads are not read or reinterpreted during GC.
    let invalid_receipt = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM source_revision_receipts r LEFT JOIN source_bindings b ON b.source_id=r.source_id LEFT JOIN source_revision_receipts c ON c.revision_id=r.content_revision_id WHERE b.source_id IS NULL OR length(r.revision_id) NOT BETWEEN 1 AND 128 OR r.revision_id GLOB '*[^A-Za-z0-9_-]*' OR length(r.source_id) NOT BETWEEN 1 AND 128 OR r.source_id GLOB '*[^A-Za-z0-9_-]*' OR r.revision_seq<1 OR r.parser_version NOT BETWEEN 1 AND 4294967295 OR r.cycle_seq<1 OR length(r.worker_boot_id) NOT BETWEEN 1 AND 128 OR r.worker_boot_id GLOB '*[^A-Za-z0-9_-]*' OR length(r.catalog_incarnation) NOT BETWEEN 1 AND 128 OR r.catalog_incarnation GLOB '*[^A-Za-z0-9_-]*' OR r.policy_epoch<0 OR r.policy_epoch>?1 OR r.started_control_seq<1 OR r.observed_at_ms<0 OR r.committed_generation<0 OR r.committed_generation>?2 OR r.committed_at_ms<0 OR length(r.revision_digest) NOT BETWEEN 1 AND 256 OR r.published NOT IN(0,1) OR (r.published=1 AND (r.completeness NOT IN('complete','append') OR r.committed_generation IS NULL OR r.committed_at_ms IS NULL OR r.content_revision_id IS NULL OR r.content_set_digest IS NULL OR r.reason IS NOT NULL)) OR (r.published=0 AND (r.completeness!='partial' OR r.committed_generation IS NOT NULL OR r.committed_at_ms IS NOT NULL OR r.content_set_digest IS NOT NULL OR r.reason IS NULL OR r.reason NOT IN('incomplete','unstable','rewrite_pending','deletion_pending'))) OR (r.content_set_digest IS NOT NULL AND (length(r.content_set_digest)!=64 OR r.content_set_digest GLOB '*[^0-9a-f]*')) OR (r.content_revision_id IS NOT NULL AND (c.revision_id IS NULL OR c.source_id!=r.source_id OR c.published!=1 OR c.content_revision_id IS NULL OR c.content_revision_id!=c.revision_id OR (c.revision_id!=r.revision_id AND c.revision_seq>=r.revision_seq) OR (r.published=1 AND (c.content_set_digest!=r.content_set_digest OR c.committed_generation>r.committed_generation)))))",
        params![snapshot.policy_epoch,snapshot.generation], |row| row.get::<_, bool>(0),
    ).map_err(sql)?;
    if invalid_receipt
        || exists(
            conn,
            "SELECT EXISTS(SELECT 1 FROM source_heads h LEFT JOIN source_bindings b USING(source_id) LEFT JOIN source_revision_receipts v ON v.revision_id=h.visible_revision_id LEFT JOIN source_revision_receipts l ON l.revision_id=h.latest_receipt_id LEFT JOIN source_revision_receipts a ON a.revision_id=h.last_attempt_id WHERE b.source_id IS NULL OR h.update_state NOT IN('unknown','current','partial','failed','deferred','paused','revoked') OR (h.visible_revision_id IS NOT NULL AND (v.revision_id IS NULL OR v.source_id!=h.source_id OR v.published!=1)) OR (h.latest_receipt_id IS NOT NULL AND (l.revision_id IS NULL OR l.source_id!=h.source_id OR l.published!=1)) OR (h.last_attempt_id IS NOT NULL AND (a.revision_id IS NULL OR a.source_id!=h.source_id)) OR (h.observed_cycle_seq IS NOT NULL AND (l.revision_id IS NULL OR h.observed_cycle_seq!=l.cycle_seq)))",
        )?
    {
        return Err(corrupt());
    }
    if exists(
        conn,
        "SELECT EXISTS(SELECT 1 FROM (SELECT source_id,revision_id FROM source_projections UNION SELECT source_id,revision_id FROM source_occurrences UNION SELECT source_id,revision_id FROM source_entity_projections UNION SELECT source_id,revision_id FROM source_session_projections) p LEFT JOIN source_revision_receipts r USING(revision_id) WHERE r.revision_id IS NULL OR r.source_id!=p.source_id OR r.published!=1) OR EXISTS(SELECT 1 FROM receipt_selection_claims WHERE selection_revision<0 OR length(selection_id) NOT BETWEEN 1 AND 128 OR selection_id GLOB '*[^A-Za-z0-9_-]*' OR length(root_identity) NOT BETWEEN 1 AND 128 OR root_identity GLOB '*[^A-Za-z0-9_-]*')",
    )? {
        return Err(corrupt());
    }
    let invalid_discovery = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM discovery_receipts WHERE cycle_seq<1 OR selection_revision<1 OR length(selection_id) NOT BETWEEN 1 AND 128 OR selection_id GLOB '*[^A-Za-z0-9_-]*' OR length(worker_boot_id) NOT BETWEEN 1 AND 128 OR worker_boot_id GLOB '*[^A-Za-z0-9_-]*' OR length(catalog_incarnation) NOT BETWEEN 1 AND 128 OR catalog_incarnation GLOB '*[^A-Za-z0-9_-]*' OR length(root_identity) NOT BETWEEN 1 AND 128 OR root_identity GLOB '*[^A-Za-z0-9_-]*' OR policy_epoch<0 OR policy_epoch>?1 OR started_control_seq<1 OR committed_generation<0 OR committed_generation>?2 OR complete NOT IN(0,1) OR length(source_set_digest)!=64 OR source_set_digest GLOB '*[^0-9a-f]*') OR EXISTS(SELECT 1 FROM discovery_sources s JOIN discovery_receipts d USING(cycle_seq,selection_id) LEFT JOIN source_revision_receipts r USING(revision_id) WHERE r.revision_id IS NULL OR r.source_id!=s.source_id OR r.published!=1 OR r.cycle_seq!=d.cycle_seq OR r.worker_boot_id!=d.worker_boot_id OR r.catalog_incarnation!=d.catalog_incarnation OR r.policy_epoch!=d.policy_epoch OR r.started_control_seq!=d.started_control_seq OR r.committed_generation>d.committed_generation OR d.complete!=1)",
        params![snapshot.policy_epoch,snapshot.generation], |row| row.get::<_, bool>(0),
    ).map_err(sql)?;
    if invalid_discovery {
        return Err(corrupt());
    }
    let invalid_origin = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM retained_source_receipts p LEFT JOIN source_revision_receipts r USING(revision_id) WHERE r.revision_id IS NULL OR r.published!=1 OR p.retained_incarnation!=?1 OR p.original_incarnation!=r.catalog_incarnation OR p.original_incarnation=p.retained_incarnation OR p.revision_digest!=r.revision_digest OR p.committed_generation!=r.committed_generation OR length(p.operation_id) NOT BETWEEN 1 AND 128 OR p.operation_id GLOB '*[^A-Za-z0-9_-]*') OR EXISTS(SELECT 1 FROM source_revision_receipts r WHERE r.published=1 AND r.catalog_incarnation!=?1 AND NOT EXISTS(SELECT 1 FROM retained_source_receipts p WHERE p.revision_id=r.revision_id AND p.retained_incarnation=?1 AND p.original_incarnation=r.catalog_incarnation AND p.revision_digest=r.revision_digest AND p.committed_generation=r.committed_generation))",
        [&snapshot.catalog_incarnation], |row| row.get::<_, bool>(0),
    ).map_err(sql)?;
    if invalid_origin {
        return Err(corrupt());
    }
    if exists(
        conn,
        "SELECT EXISTS(SELECT 1 FROM (SELECT cycle_seq,worker_boot_id FROM source_revision_receipts UNION SELECT cycle_seq,worker_boot_id FROM discovery_receipts) GROUP BY cycle_seq HAVING COUNT(DISTINCT worker_boot_id)>1)",
    )? {
        return Err(corrupt());
    }
    Ok(())
}

fn close_content_revisions(conn: &Connection) -> PortResult<()> {
    conn.execute_batch("WITH RECURSIVE closure(revision_id) AS(SELECT revision_id FROM history_keep_receipts UNION SELECT r.content_revision_id FROM source_revision_receipts r JOIN closure c ON r.revision_id=c.revision_id WHERE r.content_revision_id IS NOT NULL) INSERT OR IGNORE INTO history_keep_receipts SELECT revision_id FROM closure;").map_err(sql)
}
fn verify_live_receipts(conn: &Connection, maximum: usize, deadline: Instant) -> PortResult<()> {
    if count(conn, "SELECT COUNT(*) FROM history_keep_receipts")? > maximum as u64 {
        return Err(busy());
    }
    let mut statement = conn.prepare("SELECT k.revision_id,r.source_id FROM history_keep_receipts k LEFT JOIN source_revision_receipts r USING(revision_id) ORDER BY k.revision_id").map_err(sql)?;
    let mut rows = statement.query([]).map_err(sql)?;
    while let Some(row) = rows.next().map_err(sql)? {
        time(deadline)?;
        let revision: String = row.get(0).map_err(sql)?;
        let source: Option<String> = row.get(1).map_err(sql)?;
        let source = source.ok_or_else(corrupt)?;
        managed_receipt::read_checked(conn, &revision, Some(&source))?;
    }
    Ok(())
}
fn verify_delete_receipts(conn: &Connection, deadline: Instant) -> PortResult<()> {
    let mut statement = conn.prepare("SELECT r.revision_id,r.source_id FROM history_delete_receipts d JOIN source_revision_receipts r USING(revision_id)").map_err(sql)?;
    let mut rows = statement.query([]).map_err(sql)?;
    while let Some(row) = rows.next().map_err(sql)? {
        time(deadline)?;
        managed_receipt::read_checked(
            conn,
            &row.get::<_, String>(0).map_err(sql)?,
            Some(&row.get::<_, String>(1).map_err(sql)?),
        )?;
    }
    Ok(())
}

struct Discovery {
    cycle: i64,
    selection: String,
    selection_revision: i64,
    boot: String,
    policy: i64,
    started: i64,
    incarnation: String,
    root: String,
    digest: String,
    complete: bool,
    generation: i64,
}
impl Discovery {
    fn read(row: &Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            cycle: row.get(0)?,
            selection: row.get(1)?,
            selection_revision: row.get(2)?,
            boot: row.get(3)?,
            policy: row.get(4)?,
            started: row.get(5)?,
            incarnation: row.get(6)?,
            root: row.get(7)?,
            digest: row.get(8)?,
            complete: row.get(9)?,
            generation: row.get(10)?,
        })
    }
    fn check_receipt(&self, receipt: &RevisionRef) -> PortResult<()> {
        if !receipt.published
            || receipt.cycle_seq != self.cycle
            || receipt.worker_boot_id != self.boot
            || receipt.policy_epoch != self.policy
            || receipt.started_control_seq != self.started
            || receipt.catalog_incarnation != self.incarnation
            || receipt
                .committed_generation
                .is_none_or(|generation| generation > self.generation)
        {
            return Err(corrupt());
        }
        Ok(())
    }
}
fn verify_discoveries(conn: &Connection, maximum: usize, deadline: Instant) -> PortResult<()> {
    let mut statement = conn.prepare("SELECT d.cycle_seq,d.selection_id,d.selection_revision,d.worker_boot_id,d.policy_epoch,d.started_control_seq,d.catalog_incarnation,d.root_identity,d.source_set_digest,d.complete,d.committed_generation FROM discovery_receipts d WHERE (d.cycle_seq,d.selection_id) IN(SELECT cycle_seq,selection_id FROM history_keep_discoveries UNION SELECT cycle_seq,selection_id FROM history_delete_discoveries) ORDER BY d.cycle_seq,d.selection_id").map_err(sql)?;
    let mut rows = statement.query([]).map_err(sql)?;
    let mut dependencies = 0;
    while let Some(row) = rows.next().map_err(sql)? {
        time(deadline)?;
        let discovery = Discovery::read(row).map_err(sql)?;
        let mut sources_statement = conn.prepare("SELECT source_id,revision_id FROM discovery_sources WHERE cycle_seq=?1 AND selection_id=?2 ORDER BY source_id").map_err(sql)?;
        let mut source_rows = sources_statement
            .query(params![discovery.cycle, discovery.selection])
            .map_err(sql)?;
        let mut sources = Vec::new();
        while let Some(source_row) = source_rows.next().map_err(sql)? {
            time(deadline)?;
            dependencies += 1;
            if dependencies > maximum {
                return Err(busy());
            }
            let source = SourceId::parse(&source_row.get::<_, String>(0).map_err(sql)?)
                .map_err(|_| corrupt())?;
            let revision = RevisionId::parse(&source_row.get::<_, String>(1).map_err(sql)?)
                .map_err(|_| corrupt())?;
            let receipt =
                managed_receipt::read_checked(conn, revision.as_str(), Some(source.as_str()))?;
            discovery.check_receipt(&receipt)?;
            let claim: Option<(i64,String)> = conn.query_row("SELECT selection_revision,root_identity FROM receipt_selection_claims WHERE revision_id=?1 AND selection_id=?2",params![revision.as_str(),discovery.selection],|row|Ok((row.get(0)?,row.get(1)?))).optional().map_err(sql)?;
            if claim != Some((discovery.selection_revision, discovery.root.clone())) {
                return Err(corrupt());
            }
            sources.push(DiscoverySource {
                source_id: source,
                revision_id: revision,
            });
        }
        if (!discovery.complete && !sources.is_empty())
            || managed_discovery::source_set_digest(&sources)? != discovery.digest
        {
            return Err(corrupt());
        }
    }
    Ok(())
}

fn retained_tokens(
    conn: &Connection,
    maximum: usize,
    deadline: Instant,
) -> PortResult<CycleRetention> {
    let mut statement = conn.prepare("SELECT cycle_seq,worker_boot_id FROM source_revision_receipts UNION SELECT cycle_seq,worker_boot_id FROM discovery_receipts ORDER BY cycle_seq,worker_boot_id LIMIT ?1").map_err(sql)?;
    let mut rows = statement.query([maximum as i64 + 1]).map_err(sql)?;
    let mut tokens = BTreeMap::new();
    while let Some(row) = rows.next().map_err(sql)? {
        time(deadline)?;
        let cycle = CycleSeq::new(row.get(0).map_err(sql)?).map_err(|_| corrupt())?;
        let boot =
            ControlId::parse(&row.get::<_, String>(1).map_err(sql)?).map_err(|_| corrupt())?;
        if tokens.insert(cycle, boot).is_some() {
            return Err(corrupt());
        }
        if tokens.len() > maximum {
            return Ok(CycleRetention::PendingCatalogPrune);
        }
    }
    Ok(CycleRetention::Complete(
        tokens
            .into_iter()
            .map(|(cycle_seq, worker_boot_id)| ObservationToken {
                cycle_seq,
                worker_boot_id,
            })
            .collect(),
    ))
}
