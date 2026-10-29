//! Disposable, private cross-process continuations. Never opens the catalog.
//!
//! Call insert/page from ManagedStore::with_read with the original deadline.
//! A token is a checked reference, never authorization or freshness evidence.
//! Each operation closes its cache transaction/connection before returning an
//! owned result. The caller must still gate and bound the final emitted frame.
use crate::{
    SqliteControlStore,
    managed::ManagedRead,
    managed_locks::{ExclusiveGuard, LockKind, RootIdentity, SharedGuard},
};
use agent_session_grep_application::{
    SessionPeek,
    managed::{ManagedCandidate, ManagedCandidateSet, ManagedEvidence, ManagedPartial},
};
use agent_session_grep_domain::{IdKind, Message, StableId};
use agent_session_grep_ports::{
    PortError, SearchHit,
    control::{ControlId, ControlStore},
    managed::*,
};
use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    fmt,
    io::Write,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

pub const MAX_CANDIDATES: usize = 512;
pub const MAX_SET_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_SETS: usize = 64;
pub const MAX_TOTAL_BYTES: usize = 64 * 1024 * 1024;
pub const TTL_MS: i64 = 15 * 60 * 1000;
const APPLICATION_ID: i64 = 0x41534743;
const VERSION: i64 = 1;
// Repeated scalar columns, key and index references in addition to payload.
const SET_OVERHEAD_BYTES: usize = 512;
const SCHEMA: &str = "
CREATE TABLE cache_meta(singleton INTEGER PRIMARY KEY CHECK(singleton=1), token_key BLOB NOT NULL CHECK(length(token_key)=32), last_seen_ms INTEGER NOT NULL CHECK(last_seen_ms>=0)) STRICT;
CREATE TABLE result_sets(
 cache_id TEXT PRIMARY KEY, query_digest TEXT NOT NULL, model_digest TEXT NOT NULL,
 policy_epoch INTEGER NOT NULL CHECK(policy_epoch>=0), catalog_incarnation TEXT NOT NULL,
 generation INTEGER NOT NULL CHECK(generation>=0), destructive_epoch INTEGER NOT NULL CHECK(destructive_epoch>=0),
 created_at_ms INTEGER NOT NULL CHECK(created_at_ms>=0), expires_at_ms INTEGER NOT NULL CHECK(expires_at_ms>created_at_ms),
 size_bytes INTEGER NOT NULL CHECK(size_bytes>0 AND size_bytes<=4194304),
 row_count INTEGER NOT NULL CHECK(row_count>0 AND row_count<=512), result_payload BLOB NOT NULL
) STRICT;
CREATE TABLE result_sources(cache_id TEXT NOT NULL REFERENCES result_sets(cache_id) ON DELETE CASCADE,
 source_id TEXT NOT NULL, revision_digest TEXT NOT NULL,
 PRIMARY KEY(cache_id,source_id,revision_digest)) STRICT;
CREATE INDEX result_sets_eviction ON result_sets(created_at_ms,cache_id);
CREATE INDEX result_sources_source ON result_sources(source_id,cache_id);
";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheUnavailable {
    Busy,
    Storage,
    Corrupt,
    Oversized,
    PolicyChanged,
    Deadline,
    ClockChanged,
    InvalidCandidate,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheError {
    CursorInvalid,
    CursorExpired,
    Unavailable(CacheUnavailable),
}
impl fmt::Display for CacheError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::CursorInvalid => "invalid managed cursor",
            Self::CursorExpired => "managed cursor expired",
            Self::Unavailable(_) => "managed continuation unavailable",
        })
    }
}
impl std::error::Error for CacheError {}
type Result<T> = std::result::Result<T, CacheError>;
fn unavailable(reason: CacheUnavailable) -> CacheError {
    CacheError::Unavailable(reason)
}
fn corrupt() -> CacheError {
    unavailable(CacheUnavailable::Corrupt)
}
fn port(error: PortError) -> CacheError {
    unavailable(match error {
        PortError::WriterBusy(_) => CacheUnavailable::Busy,
        _ => CacheUnavailable::Storage,
    })
}
fn sql(error: rusqlite::Error) -> CacheError {
    use rusqlite::ErrorCode::*;
    unavailable(match error.sqlite_error_code() {
        Some(DatabaseBusy | DatabaseLocked) => CacheUnavailable::Busy,
        Some(DatabaseCorrupt | NotADatabase) => CacheUnavailable::Corrupt,
        Some(OperationInterrupted) => CacheUnavailable::Deadline,
        _ => CacheUnavailable::Storage,
    })
}
fn time_left(deadline: Instant) -> Result<Duration> {
    let left = deadline.saturating_duration_since(Instant::now());
    if left.is_zero() {
        Err(unavailable(CacheUnavailable::Deadline))
    } else {
        Ok(left)
    }
}

fn emission_admission(
    deadline: Instant,
    mut attempt: impl FnMut() -> std::result::Result<SharedGuard, PortError>,
) -> Result<SharedGuard> {
    // Another reader or a policy change can briefly hold or be acquiring this
    // root's emission lock. Use only the cache's existing 50ms busy allowance,
    // within the original deadline.
    let admission_end = deadline.min(Instant::now() + Duration::from_millis(50));
    loop {
        time_left(deadline)?;
        match attempt() {
            Ok(guard) => return Ok(guard),
            Err(PortError::WriterBusy(_)) if Instant::now() < admission_end => {
                std::thread::sleep(
                    Duration::from_millis(1)
                        .min(admission_end.saturating_duration_since(Instant::now())),
                );
            }
            Err(error) => return Err(port(error)),
        }
    }
}

/// Exact already-ranked typed candidate. No source path or transcript blob.
/// Scores and candidate ordering are copied, never recalculated by the cache.
#[derive(Clone, PartialEq)]
pub struct CacheCandidate {
    pub entry: ProjectionListEntry,
    pub score: f64,
}
impl fmt::Debug for CacheCandidate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CacheCandidate([private])")
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Digests {
    query: String,
    model: String,
    filters: String,
    grouping: String,
    order: String,
}
/// Generated together with the request predicates, so a filter cannot change
/// without changing its token binding. Raw query/model strings are not stored.
#[derive(Clone)]
pub struct CacheBinding {
    digests: Digests,
    query: ProjectionQuery,
}
impl CacheBinding {
    pub fn new(
        query: &str,
        model: &str,
        predicates: &ProjectionQuery,
        grouping: &str,
        order: &str,
    ) -> Result<Self> {
        if query.len() > 65536
            || model.len() > 4096
            || grouping.len() > 256
            || order.is_empty()
            || order.len() > 256
            || predicates
                .filters
                .repo
                .as_ref()
                .is_some_and(|v| v.len() > 512)
            || predicates
                .facets
                .tool_kind
                .as_ref()
                .is_some_and(|v| v.len() > 256)
            || predicates
                .facets
                .tool_name
                .as_ref()
                .is_some_and(|v| v.len() > 256)
            || predicates
                .filters
                .since
                .zip(predicates.filters.until)
                .is_some_and(|(a, b)| a >= b)
            || predicates
                .filters
                .since
                .is_some_and(|t| t.nanosecond >= 1_000_000_000)
            || predicates
                .filters
                .until
                .is_some_and(|t| t.nanosecond >= 1_000_000_000)
            || predicates
                .session_id
                .as_ref()
                .is_some_and(|s| s.kind() != IdKind::Session || !s.validate())
        {
            return Err(CacheError::CursorInvalid);
        }
        let mut predicates = predicates.clone();
        predicates.filters.providers.sort();
        predicates.filters.providers.dedup();
        let filters=serde_json::json!({"providers":predicates.filters.providers.iter().map(|p|p.as_str()).collect::<Vec<_>>(),
            "since":predicates.filters.since.map(|t|(t.unix_seconds,t.nanosecond)),"until":predicates.filters.until.map(|t|(t.unix_seconds,t.nanosecond)),
            "repo":predicates.filters.repo,"sidechain":predicates.facets.sidechain.as_str(),"tool_kind":predicates.facets.tool_kind,"tool_name":predicates.facets.tool_name,
            "include_system":predicates.include_system,"session":predicates.session_id.as_ref().map(StableId::as_str)}).to_string();
        Ok(Self {
            digests: Digests {
                query: digest(query.as_bytes()),
                model: digest(model.as_bytes()),
                filters: digest(filters.as_bytes()),
                grouping: digest(grouping.as_bytes()),
                order: digest(order.as_bytes()),
            },
            query: predicates,
        })
    }
}
impl fmt::Debug for CacheBinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CacheBinding([private])")
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct CacheCursor(String);
impl CacheCursor {
    pub fn as_str(&self) -> &str {
        &self.0
    }
    pub fn into_string(self) -> String {
        self.0
    }
}
impl fmt::Debug for CacheCursor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CacheCursor([private])")
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InsertOutcome {
    Stored(CacheCursor),
    Unavailable(CacheUnavailable),
}
pub struct CacheInsert<'a> {
    pub binding: &'a CacheBinding,
    pub candidates: &'a [CacheCandidate],
    pub next_offset: usize,
    /// True when the ranked window is itself incomplete. Exhausting this
    /// cached set must not be reported as exhausting the corpus.
    pub truncated: bool,
    pub now_ms: i64,
    pub deadline: Instant,
}
pub struct CachePageRequest<'a> {
    pub binding: &'a CacheBinding,
    pub cursor: &'a str,
    pub limit: usize,
    pub now_ms: i64,
    pub deadline: Instant,
}
pub struct CacheSetInsert<'a> {
    pub binding: &'a CacheBinding,
    pub set: &'a ManagedCandidateSet,
    pub next_offset: usize,
    pub now_ms: i64,
    pub deadline: Instant,
}
/// Copies are independent of SQLite. Offset tokens always reference this exact
/// checked set; holding this object grants no emission or source permission.
pub struct CacheContinuation {
    id: String,
    key: [u8; 32],
    payload_digest: [u8; 32],
    expires: i64,
    offset: usize,
    count: usize,
}
impl CacheContinuation {
    pub fn offset(&self) -> usize {
        self.offset
    }
    pub fn cursor_after(&self, emitted: usize) -> Result<Option<CacheCursor>> {
        let next = self
            .offset
            .checked_add(emitted)
            .ok_or(CacheError::CursorInvalid)?;
        if emitted == 0 || next > self.count {
            return Err(CacheError::CursorInvalid);
        }
        Ok((next < self.count).then(|| {
            token_digest(
                &self.id,
                next,
                self.expires,
                &self.payload_digest,
                &self.key,
            )
        }))
    }
}
pub struct CachedSet {
    pub set: ManagedCandidateSet,
    pub continuation: CacheContinuation,
}
pub struct CachePage {
    pub candidates: Vec<CacheCandidate>,
    pub as_of: ReadSnapshot,
    pub next_cursor: Option<CacheCursor>,
    pub truncated: bool,
}
impl fmt::Debug for CachePage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CachePage")
            .field("candidate_count", &self.candidates.len())
            .field("has_more", &self.next_cursor.is_some())
            .field("truncated", &self.truncated)
            .finish_non_exhaustive()
    }
}
/// Cache WAL cleanup only, not a catalog/source/backup purge-completion claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CachePurge {
    pub sets_removed: usize,
    pub wal_drained: bool,
}

/// Only path/physical identity survive a call; no SQLite handle or lease.
pub struct ManagedCache {
    root: PathBuf,
    physical: RootIdentity,
    installation: ControlId,
}
impl ManagedCache {
    pub fn path(root: &Path) -> PathBuf {
        root.join("continuations.db")
    }
    pub fn at(root: &Path, control: &SqliteControlStore) -> Result<Self> {
        if !root.is_absolute() {
            return Err(unavailable(CacheUnavailable::Storage));
        }
        let physical = RootIdentity::read(root).map_err(port)?;
        if !control.matches_root(physical) {
            return Err(unavailable(CacheUnavailable::PolicyChanged));
        }
        let installation = control.status().map_err(port)?.policy.installation_id;
        Ok(Self {
            root: root.into(),
            physical,
            installation,
        })
    }
    fn check(
        &self,
        control: &SqliteControlStore,
        snapshot: Option<&ReadSnapshot>,
        block_fence: bool,
    ) -> Result<()> {
        if RootIdentity::read(&self.root).map_err(port)? != self.physical
            || !control.matches_root(self.physical)
        {
            return Err(unavailable(CacheUnavailable::PolicyChanged));
        }
        // A retained connection can outlive a displaced control path. Reopen to
        // revalidate current private root/control permissions and installation.
        let fresh =
            SqliteControlStore::open_read_only(&self.root, &self.installation).map_err(port)?;
        let status = fresh.status().map_err(port)?;
        if status.policy.installation_id != self.installation
            || (block_fence && status.policy.emission_blocked())
        {
            return Err(unavailable(CacheUnavailable::PolicyChanged));
        }
        if let Some(s) = snapshot {
            validate_snapshot(s)?;
            // Catalog snapshot is the incarnation authority. A lagging control
            // progress mirror after commit must not invalidate proven content.
            if status.policy.policy_epoch.get() != s.policy_epoch {
                return Err(unavailable(CacheUnavailable::PolicyChanged));
            }
        }
        Ok(())
    }
    fn check_read(&self, control: &SqliteControlStore, read: &ManagedRead<'_>) -> Result<()> {
        let policy = read
            .authorized_policy()
            .ok_or_else(|| unavailable(CacheUnavailable::PolicyChanged))?;
        if policy.installation_id != self.installation
            || policy.policy_epoch.get() != read.snapshot().policy_epoch
            || policy.emission_blocked()
        {
            return Err(unavailable(CacheUnavailable::PolicyChanged));
        }
        self.check(control, Some(read.snapshot()), true)
    }
    fn connect(
        &self,
        control: &SqliteControlStore,
        create: bool,
        now_ms: i64,
        deadline: Instant,
    ) -> Result<Connection> {
        time_left(deadline)?;
        let path = Self::path(&self.root);
        // journal_size_limit bounds retained inactive files, not an active WAL.
        // Stop growing a cache whose reader prevents checkpoint cleanup.
        for bounded_path in [path.clone(), self.root.join("continuations.db-wal")] {
            match std::fs::symlink_metadata(bounded_path) {
                Ok(meta) if meta.len() > 80 * 1024 * 1024 => {
                    return Err(unavailable(CacheUnavailable::Oversized));
                }
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => return Err(unavailable(CacheUnavailable::Storage)),
            }
        }
        let created = match std::fs::symlink_metadata(&path) {
            Ok(_) => false,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound && create => {
                control.create_private_catalog_file(&path).map_err(port)?;
                true
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(CacheError::CursorExpired);
            }
            Err(_) => return Err(unavailable(CacheUnavailable::Storage)),
        };
        control.validate_catalog_file(&path).map_err(port)?;
        let mut conn =
            Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_WRITE).map_err(sql)?;
        conn.busy_timeout(time_left(deadline)?.min(Duration::from_millis(50)))
            .map_err(sql)?;
        conn.progress_handler(1000, Some(move || Instant::now() >= deadline))
            .map_err(sql)?;
        conn.execute_batch(
            "PRAGMA foreign_keys=ON; PRAGMA trusted_schema=OFF; PRAGMA secure_delete=ON;",
        )
        .map_err(sql)?;
        if created {
            conn.execute_batch(
                "PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA max_page_count=20480;",
            )
            .map_err(sql)?;
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(sql)?;
            tx.execute_batch(SCHEMA).map_err(sql)?;
            tx.execute(
                "INSERT INTO cache_meta VALUES(1,randomblob(32),?1)",
                [now_ms],
            )
            .map_err(sql)?;
            tx.pragma_update(None, "application_id", APPLICATION_ID)
                .map_err(sql)?;
            tx.pragma_update(None, "user_version", VERSION)
                .map_err(sql)?;
            tx.commit().map_err(sql)?;
        }
        validate_schema(&conn)?;
        conn.execute_batch("PRAGMA synchronous=FULL; PRAGMA wal_autocheckpoint=256; PRAGMA journal_size_limit=1048576; PRAGMA max_page_count=20480;").map_err(sql)?;
        control.validate_catalog_file(&path).map_err(port)?;
        if RootIdentity::read(&self.root).map_err(port)? != self.physical {
            return Err(unavailable(CacheUnavailable::PolicyChanged));
        }
        Ok(conn)
    }
    /// Complete bounded dependency inventory for history retention. The caller
    /// holds HistoryReaders exclusively, so no new continuation can appear
    /// between this inventory and catalog pruning. Missing cache means empty;
    /// malformed, busy or oversized cache means no retention is authorized.
    pub(crate) fn history_revisions(
        &self,
        control: &SqliteControlStore,
        readers: &ExclusiveGuard,
        now_ms: i64,
        deadline: Instant,
    ) -> Result<Vec<RevisionId>> {
        if readers.kind() != &LockKind::HistoryReaders || readers.root_identity() != self.physical {
            return Err(unavailable(CacheUnavailable::PolicyChanged));
        }
        readers.validate_current(&self.root).map_err(port)?;
        self.check(control, None, false)?;
        match std::fs::symlink_metadata(Self::path(&self.root)) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                for suffix in ["-wal", "-shm", "-journal"] {
                    let name = self.root.join(format!("continuations.db{suffix}"));
                    match std::fs::symlink_metadata(name) {
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                        _ => return Err(corrupt()),
                    }
                }
                return Ok(Vec::new());
            }
            Err(_) => return Err(unavailable(CacheUnavailable::Storage)),
            Ok(_) => {}
        }
        let mut conn = self.connect(control, false, now_ms, deadline)?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql)?;
        if !advance_clock(&tx, now_ms)? {
            tx.commit().map_err(sql)?;
            return Err(unavailable(CacheUnavailable::ClockChanged));
        }
        let mut revisions = BTreeSet::new();
        {
            let mut statement = tx
                .prepare("SELECT cache_id FROM result_sets ORDER BY cache_id LIMIT 65")
                .map_err(sql)?;
            let mut rows = statement.query([]).map_err(sql)?;
            let mut count = 0_usize;
            while let Some(row) = rows.next().map_err(sql)? {
                time_left(deadline)?;
                count += 1;
                if count > MAX_SETS {
                    return Err(corrupt());
                }
                let cache_id: String = row.get(0).map_err(sql)?;
                ControlId::parse(&cache_id).map_err(|_| corrupt())?;
                let value = load_set(&tx, &cache_id)?.ok_or_else(corrupt)?;
                let stored: StoredSet = decode(&value.payload)?;
                let sources = stored.validate()?;
                value.validate(&stored, &sources)?;
                if stored.installation != self.installation.as_str()
                    || stored_sources(&tx, &cache_id)? != sources
                {
                    return Err(corrupt());
                }
                for wire in &stored.candidates {
                    let candidate = wire.to_candidate()?;
                    let proof = match &candidate.entry {
                        ProjectionListEntry::Message(value) => &value.proof,
                        ProjectionListEntry::Entity(value) => &value.proof,
                    };
                    revisions.insert(proof.revision.revision_id.clone());
                    if let ProjectionListEntry::Message(value) = &candidate.entry
                        && let Some(occurrence) = &value.occurrence
                    {
                        revisions.insert(occurrence.revision.revision_id.clone());
                    }
                    if wire.output.is_some() {
                        for evidence in wire.to_managed()?.evidence {
                            revisions.insert(evidence.proof.revision.revision_id);
                            if let Some(occurrence) = evidence.occurrence {
                                revisions.insert(occurrence.revision.revision_id);
                            }
                            for related in evidence.related {
                                revisions.insert(related.revision.revision_id);
                            }
                        }
                    }
                    if revisions.len() > MAX_CANDIDATES * 2 * MAX_SETS {
                        return Err(corrupt());
                    }
                }
            }
        }
        readers.validate_current(&self.root).map_err(port)?;
        time_left(deadline)?;
        tx.commit().map_err(sql)?;
        Ok(revisions.into_iter().collect())
    }

    pub fn insert(
        &self,
        control: &SqliteControlStore,
        read: &ManagedRead<'_>,
        request: CacheInsert<'_>,
    ) -> InsertOutcome {
        match self.insert_inner(control, read, request, None) {
            Ok(cursor) => InsertOutcome::Stored(cursor),
            Err(CacheError::Unavailable(reason)) => InsertOutcome::Unavailable(reason),
            Err(_) => InsertOutcome::Unavailable(CacheUnavailable::InvalidCandidate),
        }
    }
    pub fn insert_set(
        &self,
        control: &SqliteControlStore,
        read: &ManagedRead<'_>,
        request: CacheSetInsert<'_>,
    ) -> InsertOutcome {
        let candidates = request
            .set
            .candidates
            .iter()
            .map(|c| CacheCandidate {
                entry: c.entry.clone(),
                score: c.hit.as_ref().map_or(0.0, |h| f64::from(h.score)),
            })
            .collect::<Vec<_>>();
        let result = self.insert_inner(
            control,
            read,
            CacheInsert {
                binding: request.binding,
                candidates: &candidates,
                next_offset: request.next_offset,
                truncated: request.set.truncated,
                now_ms: request.now_ms,
                deadline: request.deadline,
            },
            Some(request.set),
        );
        match result {
            Ok(c) => InsertOutcome::Stored(c),
            Err(CacheError::Unavailable(r)) => InsertOutcome::Unavailable(r),
            Err(_) => InsertOutcome::Unavailable(CacheUnavailable::InvalidCandidate),
        }
    }
    fn insert_inner(
        &self,
        control: &SqliteControlStore,
        read: &ManagedRead<'_>,
        request: CacheInsert<'_>,
        app_set: Option<&ManagedCandidateSet>,
    ) -> Result<CacheCursor> {
        let CacheInsert {
            binding,
            candidates,
            next_offset,
            truncated,
            now_ms,
            deadline,
        } = request;
        time_left(deadline)?;
        self.check_read(control, read)?;
        if app_set.is_some_and(|s| {
            s.snapshot != *read.snapshot()
                || s.request_now_ms < 0
                || s.candidates.len() != candidates.len()
        }) {
            return Err(unavailable(CacheUnavailable::InvalidCandidate));
        }
        if now_ms < 0
            || candidates.is_empty()
            || next_offset == 0
            || next_offset >= candidates.len()
        {
            return Err(unavailable(CacheUnavailable::InvalidCandidate));
        }
        if candidates.len() > MAX_CANDIDATES {
            return Err(unavailable(CacheUnavailable::Oversized));
        }
        // Reject large typed input before cloning it into the storage DTO.
        // Exact escaping/proof/index overhead is checked by the bounded writer.
        let mut input_bytes = 0usize;
        for candidate in candidates {
            time_left(deadline)?;
            let proof = match &candidate.entry {
                ProjectionListEntry::Message(p) => &p.proof,
                ProjectionListEntry::Entity(p) => &p.proof,
            };
            if proof.revision.catalog_incarnation != read.snapshot().catalog_incarnation {
                return Err(unavailable(CacheUnavailable::InvalidCandidate));
            }
            match &candidate.entry {
                ProjectionListEntry::Message(p) => {
                    input_bytes = input_bytes
                        .saturating_add(p.message.text.len())
                        .saturating_add(p.index_text.len());
                }
                ProjectionListEntry::Entity(p) => {
                    let mut count = Limited(Vec::new());
                    serde_json::to_writer(&mut count, &p.data)
                        .map_err(|_| unavailable(CacheUnavailable::Oversized))?;
                    input_bytes = input_bytes.saturating_add(count.0.len());
                }
            }
            if input_bytes > MAX_SET_BYTES {
                return Err(unavailable(CacheUnavailable::Oversized));
            }
        }
        let expires = now_ms
            .checked_add(TTL_MS)
            .ok_or_else(|| unavailable(CacheUnavailable::ClockChanged))?;
        let stored = StoredSet {
            version: 1,
            installation: self.installation.as_str().into(),
            snapshot: read.snapshot().into(),
            binding: binding.digests.clone(),
            truncated,
            context: app_set.map(|s| WireContext {
                request_now_ms: s.request_now_ms,
                partial: s.partial.iter().copied().map(WirePartial::from).collect(),
            }),
            candidates: candidates
                .iter()
                .enumerate()
                .map(|(i, c)| {
                    let mut value = WireCandidate::from_candidate(c)?;
                    value.output = app_set.map(|s| WireOutput::from_candidate(&s.candidates[i]));
                    Ok(value)
                })
                .collect::<Result<Vec<_>>>()?,
        };
        let sources = stored.validate()?;
        let payload = encode(&stored)?;
        let charge = payload
            .len()
            .checked_add(SET_OVERHEAD_BYTES)
            .ok_or_else(corrupt)?
            .checked_add(sources.iter().map(|(s, r)| s.len() + r.len() + 96).sum())
            .ok_or_else(corrupt)?;
        if charge > MAX_SET_BYTES {
            return Err(unavailable(CacheUnavailable::Oversized));
        }
        verify_candidates(read, binding, candidates, deadline)?;
        if let Some(set) = app_set {
            for candidate in &set.candidates {
                verify_output(read, binding, candidate, deadline)?;
            }
        }
        let _emission = emission_admission(deadline, || {
            SharedGuard::try_acquire(&self.root, LockKind::PolicyEmission)
        })?;
        self.check_read(control, read)?;
        let mut conn = self.connect(control, true, now_ms, deadline)?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql)?;
        if !advance_clock(&tx, now_ms)? {
            tx.commit().map_err(sql)?;
            return Err(unavailable(CacheUnavailable::ClockChanged));
        }
        tx.execute("DELETE FROM result_sets WHERE policy_epoch!=?1 OR catalog_incarnation!=?2 OR destructive_epoch!=?3",params![stored.snapshot.policy_epoch,stored.snapshot.catalog_incarnation,stored.snapshot.destructive_epoch]).map_err(sql)?;
        let mut sizes = retained_sizes(&tx)?;
        while sizes.0 >= MAX_SETS || sizes.1.saturating_add(charge) > MAX_TOTAL_BYTES {
            tx.execute("DELETE FROM result_sets WHERE cache_id=(SELECT cache_id FROM result_sets ORDER BY created_at_ms,cache_id LIMIT 1)",[]).map_err(sql)?;
            sizes = retained_sizes(&tx)?;
        }
        let id: String = tx
            .query_row("SELECT lower(hex(randomblob(16)))", [], |r| r.get(0))
            .map_err(sql)?;
        tx.execute(
            "INSERT INTO result_sets VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)",
            params![
                id,
                stored.binding.query,
                stored.binding.model,
                stored.snapshot.policy_epoch,
                stored.snapshot.catalog_incarnation,
                stored.snapshot.generation,
                stored.snapshot.destructive_epoch,
                now_ms,
                expires,
                charge as i64,
                candidates.len() as i64,
                payload
            ],
        )
        .map_err(sql)?;
        for (source, revision) in sources {
            tx.execute(
                "INSERT INTO result_sources VALUES(?1,?2,?3)",
                params![id, source, revision],
            )
            .map_err(sql)?;
        }
        let cursor = token(&id, next_offset, expires, &payload, &key(&tx)?);
        self.check_read(control, read)?;
        time_left(deadline)?;
        tx.commit().map_err(sql)?;
        Ok(cursor)
    }
    pub fn page(
        &self,
        control: &SqliteControlStore,
        read: &ManagedRead<'_>,
        request: CachePageRequest<'_>,
    ) -> Result<CachePage> {
        // Parse before any cache filesystem access; old stateless tokens fail.
        let parsed = parse_token(request.cursor)?;
        if request.limit == 0 || request.limit > MAX_CANDIDATES || request.now_ms < 0 {
            return Err(CacheError::CursorInvalid);
        }
        let limit = request.limit;
        self.load_inner(control, read, request, parsed)
            .and_then(|(stored, continuation)| {
                let end = continuation
                    .offset
                    .saturating_add(limit)
                    .min(stored.candidates.len());
                let candidates = stored.candidates[continuation.offset..end]
                    .iter()
                    .map(WireCandidate::to_candidate)
                    .collect::<Result<Vec<_>>>()?;
                let next_cursor = continuation.cursor_after(end - continuation.offset)?;
                Ok(CachePage {
                    candidates,
                    as_of: stored.snapshot.into(),
                    next_cursor,
                    truncated: stored.truncated,
                })
            })
            .map_err(|e| match e {
                CacheError::CursorInvalid => e,
                _ => CacheError::CursorExpired,
            })
    }
    pub fn load_set(
        &self,
        control: &SqliteControlStore,
        read: &ManagedRead<'_>,
        request: CachePageRequest<'_>,
    ) -> Result<CachedSet> {
        let parsed = parse_token(request.cursor)?;
        self.load_inner(control, read, request, parsed)
            .and_then(|(stored, continuation)| {
                let context = stored.context.ok_or_else(corrupt)?;
                let candidates = stored
                    .candidates
                    .iter()
                    .map(WireCandidate::to_managed)
                    .collect::<Result<Vec<_>>>()?;
                Ok(CachedSet {
                    set: ManagedCandidateSet {
                        candidates,
                        snapshot: stored.snapshot.into(),
                        request_now_ms: context.request_now_ms,
                        partial: context
                            .partial
                            .into_iter()
                            .map(ManagedPartial::from)
                            .collect(),
                        truncated: stored.truncated,
                    },
                    continuation,
                })
            })
            .map_err(|e| match e {
                CacheError::CursorInvalid => e,
                _ => CacheError::CursorExpired,
            })
    }
    fn load_inner(
        &self,
        control: &SqliteControlStore,
        read: &ManagedRead<'_>,
        request: CachePageRequest<'_>,
        parsed: ParsedToken,
    ) -> Result<(StoredSet, CacheContinuation)> {
        self.check_read(control, read)?;
        let mut conn = self.connect(control, false, request.now_ms, request.deadline)?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql)?;
        if !advance_clock(&tx, request.now_ms)? {
            tx.commit().map_err(sql)?;
            return Err(CacheError::CursorExpired);
        }
        let Some(row) = load_set(&tx, &parsed.id)? else {
            // Persist TTL/high-water cleanup even when this particular set has
            // expired or was evicted; no failure silently resets the clock.
            tx.commit().map_err(sql)?;
            return Err(CacheError::CursorExpired);
        };
        let stored: StoredSet = decode(&row.payload)?;
        let sources = stored.validate()?;
        row.validate(&stored, &sources)?;
        if stored_sources(&tx, &parsed.id)? != sources {
            return Err(corrupt());
        }
        if stored.installation != self.installation.as_str()
            || stored.snapshot.policy_epoch != read.snapshot().policy_epoch
            || stored.snapshot.catalog_incarnation != read.snapshot().catalog_incarnation
            || stored.snapshot.destructive_epoch != read.snapshot().destructive_epoch
            || stored.snapshot.generation > read.snapshot().generation
            || stored.binding.model != request.binding.digests.model
        {
            return Err(CacheError::CursorExpired);
        }
        if stored.binding != request.binding.digests
            || parsed.offset >= stored.candidates.len()
            || parsed.expires != row.expires
            || token(
                &parsed.id,
                parsed.offset,
                parsed.expires,
                &row.payload,
                &key(&tx)?,
            )
            .as_str()
                != request.cursor
        {
            return Err(CacheError::CursorInvalid);
        }
        if request.now_ms < row.created || request.now_ms >= row.expires {
            return Err(CacheError::CursorExpired);
        }
        let allowed = read
            .source_progress()
            .map_err(port)?
            .into_iter()
            .map(|p| p.source_id.as_str().to_owned())
            .collect::<BTreeSet<_>>();
        if sources.iter().any(|(s, _)| !allowed.contains(s)) {
            return Err(CacheError::CursorExpired);
        }
        let key = key(&tx)?;
        let continuation = CacheContinuation {
            id: parsed.id,
            key,
            payload_digest: *blake3::hash(&row.payload).as_bytes(),
            expires: row.expires,
            offset: parsed.offset,
            count: stored.candidates.len(),
        };
        self.check_read(control, read)?;
        time_left(request.deadline)?;
        tx.commit().map_err(sql)?;
        Ok((stored, continuation))
    }
    /// Logical invalidation under an actual emission drain. wal_drained=false
    /// means physical WAL cleanup still waits; never claim purge completion.
    pub fn purge_all(
        &self,
        control: &SqliteControlStore,
        drain: &ExclusiveGuard,
        deadline: Instant,
    ) -> Result<CachePurge> {
        if drain.kind() != &LockKind::PolicyEmission || drain.root_identity() != self.physical {
            return Err(unavailable(CacheUnavailable::PolicyChanged));
        }
        self.check(control, None, false)?;
        match std::fs::symlink_metadata(Self::path(&self.root)) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                for suffix in ["-wal", "-shm", "-journal"] {
                    match std::fs::symlink_metadata(
                        self.root.join(format!("continuations.db{suffix}")),
                    ) {
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                        _ => return Err(unavailable(CacheUnavailable::Corrupt)),
                    }
                }
                return Ok(CachePurge {
                    sets_removed: 0,
                    wal_drained: true,
                });
            }
            Err(_) => return Err(unavailable(CacheUnavailable::Storage)),
            Ok(_) => {}
        }
        let mut conn = self.connect(control, false, 0, deadline)?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql)?;
        let sets_removed = tx.execute("DELETE FROM result_sets", []).map_err(sql)?;
        tx.execute(
            "UPDATE cache_meta SET token_key=randomblob(32) WHERE singleton=1",
            [],
        )
        .map_err(sql)?;
        tx.commit().map_err(sql)?;
        let busy: i64 = conn
            .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |r| r.get(0))
            .map_err(sql)?;
        Ok(CachePurge {
            sets_removed,
            wal_drained: busy == 0,
        })
    }
}

fn validate_snapshot(s: &ReadSnapshot) -> Result<()> {
    if s.generation < 0
        || s.policy_epoch < 0
        || s.destructive_epoch < 0
        || ControlId::parse(&s.catalog_incarnation).is_err()
    {
        return Err(corrupt());
    }
    Ok(())
}
fn verify_candidates(
    read: &ManagedRead<'_>,
    binding: &CacheBinding,
    candidates: &[CacheCandidate],
    deadline: Instant,
) -> Result<()> {
    for c in candidates {
        time_left(deadline)?;
        let valid = read
            .verify_cache_entry(&c.entry, &binding.query)
            .map_err(port)?;
        if !valid {
            return Err(unavailable(CacheUnavailable::InvalidCandidate));
        }
    }
    Ok(())
}

fn verify_output(
    read: &ManagedRead<'_>,
    binding: &CacheBinding,
    candidate: &ManagedCandidate,
    deadline: Instant,
) -> Result<()> {
    time_left(deadline)?;
    if candidate.evidence.is_empty()
        || candidate.evidence.len() > 64
        || !read
            .verify_cache_evidence(&candidate.evidence, &binding.query)
            .map_err(port)?
    {
        return Err(unavailable(CacheUnavailable::InvalidCandidate));
    }
    if let Some(hit) = &candidate.hit
        && (hit.id != *candidate.entry.id()
            || !hit.score.is_finite()
            || hit.occurrences == 0
            || hit.occurrences > MAX_CANDIDATES)
    {
        return Err(unavailable(CacheUnavailable::InvalidCandidate));
    }
    Ok(())
}

fn validate_schema(conn: &Connection) -> Result<()> {
    let version: i64 = conn
        .pragma_query_value(None, "user_version", |r| r.get(0))
        .map_err(sql)?;
    let app: i64 = conn
        .pragma_query_value(None, "application_id", |r| r.get(0))
        .map_err(sql)?;
    let mode: String = conn
        .pragma_query_value(None, "journal_mode", |r| r.get(0))
        .map_err(sql)?;
    if version != VERSION || app != APPLICATION_ID || mode != "wal" {
        return Err(corrupt());
    }
    let mut stmt = conn
        .prepare("SELECT name FROM sqlite_schema WHERE type='table' ORDER BY name")
        .map_err(sql)?;
    let tables = stmt
        .query_map([], |r| r.get::<_, String>(0))
        .map_err(sql)?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(sql)?;
    if tables != ["cache_meta", "result_sets", "result_sources"] {
        return Err(corrupt());
    }
    let unexpected: i64 = conn
        .query_row(
            "SELECT count(*) FROM sqlite_schema WHERE type IN('view','trigger')",
            [],
            |r| r.get(0),
        )
        .map_err(sql)?;
    let strict:i64=conn.query_row("SELECT count(*) FROM pragma_table_list WHERE schema='main' AND name IN('cache_meta','result_sets','result_sources') AND strict=1",[],|r|r.get(0)).map_err(sql)?;
    if unexpected != 0 || strict != 3 {
        return Err(corrupt());
    }
    for (name, sql_text) in [
        (
            "cache_meta",
            "SELECT singleton,token_key,last_seen_ms FROM cache_meta",
        ),
        (
            "result_sets",
            "SELECT cache_id,query_digest,model_digest,policy_epoch,catalog_incarnation,generation,destructive_epoch,created_at_ms,expires_at_ms,size_bytes,row_count,result_payload FROM result_sets",
        ),
        (
            "result_sources",
            "SELECT cache_id,source_id,revision_digest FROM result_sources",
        ),
    ] {
        let columns: i64 = conn
            .query_row("SELECT count(*) FROM pragma_table_info(?1)", [name], |r| {
                r.get(0)
            })
            .map_err(sql)?;
        let stmt = conn.prepare(sql_text).map_err(sql)?;
        if columns != stmt.column_count() as i64 {
            return Err(corrupt());
        }
    }
    let count: i64 = conn
        .query_row("SELECT count(*) FROM cache_meta", [], |r| r.get(0))
        .map_err(sql)?;
    if count != 1 {
        return Err(corrupt());
    }
    key(conn)?;
    let clock: i64 = conn
        .query_row(
            "SELECT last_seen_ms FROM cache_meta WHERE singleton=1",
            [],
            |r| r.get(0),
        )
        .map_err(sql)?;
    if clock < 0 {
        return Err(corrupt());
    }
    let orphan:i64=conn.query_row("SELECT EXISTS(SELECT 1 FROM result_sources s WHERE NOT EXISTS(SELECT 1 FROM result_sets r WHERE r.cache_id=s.cache_id))",[],|r|r.get(0)).map_err(sql)?;
    if orphan != 0 {
        return Err(corrupt());
    }
    retained_sizes(conn)?;
    Ok(())
}
fn retained_sizes(conn: &Connection) -> Result<(usize, usize)> {
    let (count,size,bad):(i64,i64,i64)=conn.query_row("SELECT count(*),coalesce(sum(size_bytes),0),coalesce(sum(size_bytes<length(result_payload) OR size_bytes>4194304 OR size_bytes<1 OR row_count<1 OR row_count>512 OR expires_at_ms<=created_at_ms OR expires_at_ms-created_at_ms!=900000 OR created_at_ms<0),0) FROM result_sets",[],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).map_err(sql)?;
    if count < 0 || count > MAX_SETS as i64 || size < 0 || size > MAX_TOTAL_BYTES as i64 || bad != 0
    {
        return Err(corrupt());
    }
    Ok((count as usize, size as usize))
}
fn advance_clock(conn: &Connection, now: i64) -> Result<bool> {
    if now < 0 {
        return Err(unavailable(CacheUnavailable::ClockChanged));
    }
    let previous: i64 = conn
        .query_row(
            "SELECT last_seen_ms FROM cache_meta WHERE singleton=1",
            [],
            |r| r.get(0),
        )
        .map_err(sql)?;
    if previous < 0 {
        return Err(corrupt());
    }
    if now < previous {
        conn.execute("DELETE FROM result_sets", []).map_err(sql)?;
    }
    conn.execute(
        "UPDATE cache_meta SET last_seen_ms=?1 WHERE singleton=1",
        [now],
    )
    .map_err(sql)?;
    conn.execute("DELETE FROM result_sets WHERE expires_at_ms<=?1", [now])
        .map_err(sql)?;
    Ok(now >= previous)
}
fn key(conn: &Connection) -> Result<[u8; 32]> {
    let key: Vec<u8> = conn
        .query_row(
            "SELECT token_key FROM cache_meta WHERE singleton=1",
            [],
            |r| r.get(0),
        )
        .map_err(sql)?;
    key.try_into().map_err(|_| corrupt())
}
fn digest(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}
fn token(id: &str, offset: usize, expires: i64, payload: &[u8], key: &[u8; 32]) -> CacheCursor {
    token_digest(id, offset, expires, blake3::hash(payload).as_bytes(), key)
}
fn token_digest(
    id: &str,
    offset: usize,
    expires: i64,
    payload_digest: &[u8; 32],
    key: &[u8; 32],
) -> CacheCursor {
    let prefix = format!("asgmc1.{id}.{offset}.{expires}");
    let mut hash = blake3::Hasher::new_keyed(key);
    hash.update(b"asg-managed-continuation-v1\0");
    hash.update(prefix.as_bytes());
    hash.update(payload_digest);
    CacheCursor(format!("{prefix}.{}", hash.finalize().to_hex()))
}
struct ParsedToken {
    id: String,
    offset: usize,
    expires: i64,
}
fn parse_token(value: &str) -> Result<ParsedToken> {
    if value.len() > 192 || !value.is_ascii() {
        return Err(CacheError::CursorInvalid);
    }
    let parts = value.split('.').collect::<Vec<_>>();
    let hex = |s: &str, n| {
        s.len() == n
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    };
    if parts.len() != 5 || parts[0] != "asgmc1" || !hex(parts[1], 32) || !hex(parts[4], 64) {
        return Err(CacheError::CursorInvalid);
    }
    let offset = parts[2]
        .parse::<usize>()
        .map_err(|_| CacheError::CursorInvalid)?;
    let expires = parts[3]
        .parse::<i64>()
        .map_err(|_| CacheError::CursorInvalid)?;
    if offset == 0
        || offset >= MAX_CANDIDATES
        || expires < 0
        || offset.to_string() != parts[2]
        || expires.to_string() != parts[3]
    {
        return Err(CacheError::CursorInvalid);
    }
    Ok(ParsedToken {
        id: parts[1].into(),
        offset,
        expires,
    })
}

struct Row {
    query: String,
    model: String,
    snapshot: ReadSnapshot,
    created: i64,
    expires: i64,
    charge: i64,
    count: i64,
    payload: Vec<u8>,
}
fn load_set(conn: &Connection, id: &str) -> Result<Option<Row>> {
    conn.query_row("SELECT query_digest,model_digest,policy_epoch,catalog_incarnation,generation,destructive_epoch,created_at_ms,expires_at_ms,size_bytes,row_count,result_payload FROM result_sets WHERE cache_id=?1 AND length(result_payload)<=4194304",[id],|r|Ok(Row {query:r.get(0)?,model:r.get(1)?,snapshot:ReadSnapshot{policy_epoch:r.get(2)?,catalog_incarnation:r.get(3)?,generation:r.get(4)?,destructive_epoch:r.get(5)?},created:r.get(6)?,expires:r.get(7)?,charge:r.get(8)?,count:r.get(9)?,payload:r.get(10)?})).optional().map_err(sql)
}
fn stored_sources(conn: &Connection, id: &str) -> Result<BTreeSet<(String, String)>> {
    let mut statement=conn.prepare("SELECT source_id,revision_digest FROM result_sources WHERE cache_id=?1 ORDER BY source_id,revision_digest LIMIT 1025").map_err(sql)?;
    let sources = statement
        .query_map([id], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
        })
        .map_err(sql)?
        .collect::<std::result::Result<BTreeSet<_>, _>>()
        .map_err(sql)?;
    if sources.len() > MAX_CANDIDATES * 2 {
        return Err(corrupt());
    }
    Ok(sources)
}
impl Row {
    fn validate(&self, s: &StoredSet, sources: &BTreeSet<(String, String)>) -> Result<()> {
        let snapshot: ReadSnapshot = s.snapshot.clone().into();
        if self.query != s.binding.query
            || self.model != s.binding.model
            || self.snapshot != snapshot
            || self.count != s.candidates.len() as i64
            || self.charge
                != (self.payload.len()
                    + SET_OVERHEAD_BYTES
                    + sources
                        .iter()
                        .map(|(a, b)| a.len() + b.len() + 96)
                        .sum::<usize>()) as i64
            || self.created < 0
            || self.created.checked_add(TTL_MS) != Some(self.expires)
        {
            return Err(corrupt());
        }
        Ok(())
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireSnapshot {
    catalog_incarnation: String,
    generation: i64,
    destructive_epoch: i64,
    policy_epoch: i64,
}
impl From<&ReadSnapshot> for WireSnapshot {
    fn from(s: &ReadSnapshot) -> Self {
        Self {
            catalog_incarnation: s.catalog_incarnation.clone(),
            generation: s.generation,
            destructive_epoch: s.destructive_epoch,
            policy_epoch: s.policy_epoch,
        }
    }
}
impl From<WireSnapshot> for ReadSnapshot {
    fn from(s: WireSnapshot) -> Self {
        Self {
            catalog_incarnation: s.catalog_incarnation,
            generation: s.generation,
            destructive_epoch: s.destructive_epoch,
            policy_epoch: s.policy_epoch,
        }
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireRevision {
    revision_id: String,
    digest: String,
    observed_at_ms: i64,
    cycle_seq: i64,
    worker_boot_id: String,
    catalog_incarnation: String,
    policy_epoch: i64,
    started_control_seq: i64,
    committed_generation: Option<i64>,
    published: bool,
}
impl From<&RevisionRef> for WireRevision {
    fn from(r: &RevisionRef) -> Self {
        Self {
            revision_id: r.revision_id.as_str().into(),
            digest: r.digest.clone(),
            observed_at_ms: r.observed_at_ms,
            cycle_seq: r.cycle_seq,
            worker_boot_id: r.worker_boot_id.clone(),
            catalog_incarnation: r.catalog_incarnation.clone(),
            policy_epoch: r.policy_epoch,
            started_control_seq: r.started_control_seq,
            committed_generation: r.committed_generation,
            published: r.published,
        }
    }
}
impl WireRevision {
    fn read(&self) -> Result<RevisionRef> {
        if !self.published
            || self.observed_at_ms < 0
            || self.cycle_seq < 1
            || self.policy_epoch < 0
            || self.started_control_seq < 1
            || self.committed_generation.is_none_or(|g| g < 0)
            || self.digest.is_empty()
            || self.digest.len() > 256
            || self.digest.chars().any(char::is_control)
            || ControlId::parse(&self.worker_boot_id).is_err()
            || ControlId::parse(&self.catalog_incarnation).is_err()
        {
            return Err(corrupt());
        }
        Ok(RevisionRef {
            revision_id: RevisionId::parse(&self.revision_id).map_err(|_| corrupt())?,
            digest: self.digest.clone(),
            observed_at_ms: self.observed_at_ms,
            cycle_seq: self.cycle_seq,
            worker_boot_id: self.worker_boot_id.clone(),
            catalog_incarnation: self.catalog_incarnation.clone(),
            policy_epoch: self.policy_epoch,
            started_control_seq: self.started_control_seq,
            committed_generation: self.committed_generation,
            published: self.published,
        })
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireProof {
    source: String,
    projection: String,
    revision: WireRevision,
}
impl From<&EvidenceProof> for WireProof {
    fn from(p: &EvidenceProof) -> Self {
        Self {
            source: p.source_id.as_str().into(),
            projection: p.projection_id.as_str().into(),
            revision: (&p.revision).into(),
        }
    }
}
impl WireProof {
    fn read(&self) -> Result<EvidenceProof> {
        Ok(EvidenceProof {
            source_id: SourceId::parse(&self.source).map_err(|_| corrupt())?,
            projection_id: ProjectionId::parse(&self.projection).map_err(|_| corrupt())?,
            revision: self.revision.read()?,
        })
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireOccurrence {
    data: OccurrenceData,
    source: String,
    revision: WireRevision,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind", deny_unknown_fields)]
enum WireEntry {
    Message {
        message: Message,
        index_text: String,
        payload_digest: String,
        index_digest: String,
        proof: WireProof,
        occurrence: Option<Box<WireOccurrence>>,
    },
    Entity {
        data: Box<EntityData>,
        proof: WireProof,
    },
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireCandidate {
    score: f64,
    entry: WireEntry,
    output: Option<WireOutput>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireOutput {
    hit: Option<WireHit>,
    evidence: Vec<WireEvidence>,
    peek: Option<WirePeek>,
    title: Option<String>,
}
impl WireOutput {
    fn from_candidate(c: &ManagedCandidate) -> Self {
        Self {
            hit: c.hit.as_ref().map(WireHit::from),
            evidence: c.evidence.iter().map(WireEvidence::from).collect(),
            peek: c.peek.as_ref().map(|p| WirePeek {
                first_user_text: p.first_user_text.clone(),
                last_user_text: p.last_user_text.clone(),
            }),
            title: c.title.clone(),
        }
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireHit {
    id: StableId,
    score: f32,
    session_id: Option<String>,
    text: Option<String>,
    why_matched: Vec<String>,
    suggested_next_commands: Vec<String>,
    occurrences: usize,
    resume_available: bool,
}
impl From<&SearchHit> for WireHit {
    fn from(h: &SearchHit) -> Self {
        Self {
            id: h.id.clone(),
            score: h.score,
            session_id: h.session_id.clone(),
            text: h.text.clone(),
            why_matched: h.why_matched.clone(),
            suggested_next_commands: h.suggested_next_commands.clone(),
            occurrences: h.occurrences,
            resume_available: h.resume_available,
        }
    }
}
impl WireHit {
    fn read(&self) -> Result<SearchHit> {
        if !self.id.validate()
            || !self.score.is_finite()
            || self.occurrences == 0
            || self.occurrences > MAX_CANDIDATES
            || self.why_matched.len() > 512
            || self.suggested_next_commands.len() > 64
        {
            return Err(corrupt());
        }
        Ok(SearchHit {
            id: self.id.clone(),
            score: self.score,
            session_id: self.session_id.clone(),
            text: self.text.clone(),
            why_matched: self.why_matched.clone(),
            suggested_next_commands: self.suggested_next_commands.clone(),
            occurrences: self.occurrences,
            resume_available: self.resume_available,
        })
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WirePeek {
    first_user_text: Option<String>,
    last_user_text: Option<String>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireEvidence {
    entity_id: StableId,
    proof: WireProof,
    occurrence: Option<WireOccurrence>,
    related: Vec<WireProof>,
}
impl From<&ManagedEvidence> for WireEvidence {
    fn from(e: &ManagedEvidence) -> Self {
        Self {
            entity_id: e.entity_id.clone(),
            proof: (&e.proof).into(),
            occurrence: e.occurrence.as_ref().map(|o| WireOccurrence {
                data: o.data.clone(),
                source: o.source_id.as_str().into(),
                revision: (&o.revision).into(),
            }),
            related: e.related.iter().map(WireProof::from).collect(),
        }
    }
}
impl WireEvidence {
    fn read(&self) -> Result<ManagedEvidence> {
        if !self.entity_id.validate()
            || self.entity_id.kind() == IdKind::Source
            || self.related.len() > 64
        {
            return Err(corrupt());
        }
        Ok(ManagedEvidence {
            entity_id: self.entity_id.clone(),
            proof: self.proof.read()?,
            occurrence: self
                .occurrence
                .as_ref()
                .map(|o| {
                    Ok(OccurrenceProjection {
                        data: o.data.clone(),
                        source_id: SourceId::parse(&o.source).map_err(|_| corrupt())?,
                        revision: o.revision.read()?,
                    })
                })
                .transpose()?,
            related: self
                .related
                .iter()
                .map(WireProof::read)
                .collect::<Result<Vec<_>>>()?,
        })
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireContext {
    request_now_ms: i64,
    partial: Vec<WirePartial>,
}
#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum WirePartial {
    ContinuationUnavailable,
    RankingWindow,
    ResponseBudget,
    MetadataSearchUnavailable,
    ResumeAvailabilityUnavailable,
    ListPreviewUnavailable,
    SemanticUnavailable,
    AggregateFactsUnavailable,
    HandoffEnrichmentUnavailable,
    ContextUnavailable,
    RetainedEvidence,
}
impl From<ManagedPartial> for WirePartial {
    fn from(p: ManagedPartial) -> Self {
        match p {
            ManagedPartial::ContinuationUnavailable => Self::ContinuationUnavailable,
            ManagedPartial::RankingWindow => Self::RankingWindow,
            ManagedPartial::ResponseBudget => Self::ResponseBudget,
            ManagedPartial::MetadataSearchUnavailable => Self::MetadataSearchUnavailable,
            ManagedPartial::ResumeAvailabilityUnavailable => Self::ResumeAvailabilityUnavailable,
            ManagedPartial::ListPreviewUnavailable => Self::ListPreviewUnavailable,
            ManagedPartial::SemanticUnavailable => Self::SemanticUnavailable,
            ManagedPartial::AggregateFactsUnavailable => Self::AggregateFactsUnavailable,
            ManagedPartial::HandoffEnrichmentUnavailable => Self::HandoffEnrichmentUnavailable,
            ManagedPartial::ContextUnavailable => Self::ContextUnavailable,
            ManagedPartial::RetainedEvidence => Self::RetainedEvidence,
        }
    }
}
impl From<WirePartial> for ManagedPartial {
    fn from(p: WirePartial) -> Self {
        match p {
            WirePartial::ContinuationUnavailable => Self::ContinuationUnavailable,
            WirePartial::RankingWindow => Self::RankingWindow,
            WirePartial::ResponseBudget => Self::ResponseBudget,
            WirePartial::MetadataSearchUnavailable => Self::MetadataSearchUnavailable,
            WirePartial::ResumeAvailabilityUnavailable => Self::ResumeAvailabilityUnavailable,
            WirePartial::ListPreviewUnavailable => Self::ListPreviewUnavailable,
            WirePartial::SemanticUnavailable => Self::SemanticUnavailable,
            WirePartial::AggregateFactsUnavailable => Self::AggregateFactsUnavailable,
            WirePartial::HandoffEnrichmentUnavailable => Self::HandoffEnrichmentUnavailable,
            WirePartial::ContextUnavailable => Self::ContextUnavailable,
            WirePartial::RetainedEvidence => Self::RetainedEvidence,
        }
    }
}
impl WireCandidate {
    fn from_candidate(c: &CacheCandidate) -> Result<Self> {
        if !c.score.is_finite() {
            return Err(unavailable(CacheUnavailable::InvalidCandidate));
        }
        let entry = match &c.entry {
            ProjectionListEntry::Message(p) => WireEntry::Message {
                message: p.message.clone(),
                index_text: p.index_text.clone(),
                payload_digest: p.payload_digest.clone(),
                index_digest: p.index_digest.clone(),
                proof: (&p.proof).into(),
                occurrence: p.occurrence.as_ref().map(|o| {
                    Box::new(WireOccurrence {
                        data: o.data.clone(),
                        source: o.source_id.as_str().into(),
                        revision: (&o.revision).into(),
                    })
                }),
            },
            ProjectionListEntry::Entity(p) => WireEntry::Entity {
                data: Box::new(p.data.clone()),
                proof: (&p.proof).into(),
            },
        };
        Ok(Self {
            score: c.score,
            entry,
            output: None,
        })
    }
    fn to_managed(&self) -> Result<ManagedCandidate> {
        let candidate = self.to_candidate()?;
        let output = self.output.as_ref().ok_or_else(corrupt)?;
        let hit = output.hit.as_ref().map(WireHit::read).transpose()?;
        let evidence = output
            .evidence
            .iter()
            .map(WireEvidence::read)
            .collect::<Result<Vec<_>>>()?;
        if hit.as_ref().is_some_and(|h| h.id != *candidate.entry.id())
            || evidence.is_empty()
            || evidence.len() > 64
        {
            return Err(corrupt());
        }
        Ok(ManagedCandidate {
            entry: candidate.entry,
            hit,
            evidence,
            peek: output.peek.as_ref().map(|p| SessionPeek {
                first_user_text: p.first_user_text.clone(),
                last_user_text: p.last_user_text.clone(),
            }),
            title: output.title.clone(),
        })
    }
    fn to_candidate(&self) -> Result<CacheCandidate> {
        if !self.score.is_finite() {
            return Err(corrupt());
        }
        let entry = match &self.entry {
            WireEntry::Message {
                message,
                index_text,
                payload_digest,
                index_digest,
                proof,
                occurrence,
            } => {
                message.validate().map_err(|_| corrupt())?;
                let occurrence = occurrence
                    .as_ref()
                    .map(|o| {
                        Ok(OccurrenceProjection {
                            data: o.data.clone(),
                            source_id: SourceId::parse(&o.source).map_err(|_| corrupt())?,
                            revision: o.revision.read()?,
                        })
                    })
                    .transpose()?;
                ProjectionListEntry::Message(Box::new(MessageProjection {
                    message: message.clone(),
                    index_text: index_text.clone(),
                    payload_digest: payload_digest.clone(),
                    index_digest: index_digest.clone(),
                    proof: proof.read()?,
                    occurrence,
                }))
            }
            WireEntry::Entity { data, proof } => {
                match data.as_ref() {
                    EntityData::Session(s) => s.session.validate().map_err(|_| corrupt())?,
                    EntityData::Document(d) => d.validate().map_err(|_| corrupt())?,
                    _ => return Err(corrupt()),
                };
                ProjectionListEntry::Entity(Box::new(EntityProjection {
                    data: *data.clone(),
                    proof: proof.read()?,
                }))
            }
        };
        Ok(CacheCandidate {
            entry,
            score: self.score,
        })
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredSet {
    version: u32,
    installation: String,
    snapshot: WireSnapshot,
    binding: Digests,
    truncated: bool,
    context: Option<WireContext>,
    candidates: Vec<WireCandidate>,
}
impl StoredSet {
    fn validate(&self) -> Result<BTreeSet<(String, String)>> {
        let snapshot: ReadSnapshot = self.snapshot.clone().into();
        validate_snapshot(&snapshot)?;
        if self.version != 1
            || ControlId::parse(&self.installation).is_err()
            || self.candidates.is_empty()
            || self.candidates.len() > MAX_CANDIDATES
        {
            return Err(corrupt());
        }
        for d in [
            &self.binding.query,
            &self.binding.model,
            &self.binding.filters,
            &self.binding.grouping,
            &self.binding.order,
        ] {
            if d.len() != 64
                || !d
                    .bytes()
                    .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
            {
                return Err(corrupt());
            }
        }
        let mut ids = BTreeSet::new();
        let mut sources = BTreeSet::new();
        if self
            .context
            .as_ref()
            .is_some_and(|c| c.request_now_ms < 0 || c.partial.len() > 64)
        {
            return Err(corrupt());
        }
        for wire in &self.candidates {
            if self.context.is_some() != wire.output.is_some() {
                return Err(corrupt());
            }
            let c = wire.to_candidate()?;
            if !ids.insert(c.entry.id().as_str().to_owned()) {
                return Err(corrupt());
            }
            let proof = match &c.entry {
                ProjectionListEntry::Message(p) => &p.proof,
                ProjectionListEntry::Entity(p) => &p.proof,
            };
            let mut add = |source: &SourceId, revision: &RevisionRef| -> Result<()> {
                if revision.catalog_incarnation != snapshot.catalog_incarnation
                    || revision.policy_epoch > snapshot.policy_epoch
                    || revision
                        .committed_generation
                        .is_none_or(|g| g > snapshot.generation)
                {
                    return Err(corrupt());
                }
                sources.insert((source.as_str().into(), revision.digest.clone()));
                Ok(())
            };
            add(&proof.source_id, &proof.revision)?;
            if let ProjectionListEntry::Message(p) = &c.entry
                && let Some(o) = &p.occurrence
            {
                if o.data.placement.message_id != p.message.id
                    || o.source_id != p.proof.source_id
                    || !o.data.placement.session_id.validate()
                    || !o.data.placement.source_document_id.validate()
                {
                    return Err(corrupt());
                }
                add(&o.source_id, &o.revision)?;
            }
            if wire.output.is_some() {
                let candidate = wire.to_managed()?;
                for evidence in candidate.evidence {
                    add(&evidence.proof.source_id, &evidence.proof.revision)?;
                    if let Some(o) = evidence.occurrence {
                        add(&o.source_id, &o.revision)?;
                    }
                    for related in evidence.related {
                        add(&related.source_id, &related.revision)?;
                    }
                }
            }
        }
        Ok(sources)
    }
}

struct Limited(Vec<u8>);
impl Write for Limited {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        if self.0.len().saturating_add(b.len()) > MAX_SET_BYTES {
            return Err(std::io::ErrorKind::OutOfMemory.into());
        }
        self.0.extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
fn encode(value: &StoredSet) -> Result<Vec<u8>> {
    let mut output = Limited(vec![0; 32]);
    serde_json::to_writer(&mut output, value)
        .map_err(|_| unavailable(CacheUnavailable::Oversized))?;
    let checksum = blake3::hash(&output.0[32..]);
    output.0[..32].copy_from_slice(checksum.as_bytes());
    Ok(output.0)
}
fn decode(bytes: &[u8]) -> Result<StoredSet> {
    if bytes.len() > MAX_SET_BYTES
        || bytes.len() < 32
        || blake3::hash(&bytes[32..]).as_bytes() != &bytes[..32]
    {
        return Err(corrupt());
    }
    serde_json::from_slice(&bytes[32..]).map_err(|_| corrupt())
}

#[cfg(test)]
mod admission_tests {
    use super::*;

    #[test]
    fn transient_registry_busy_uses_same_budget_and_real_exclusive_gate_stays_busy() {
        let root = agent_session_grep_testkit::tempdir().unwrap();
        let mut attempts = 0;
        let deadline = Instant::now() + Duration::from_secs(1);
        let held = emission_admission(deadline, || {
            attempts += 1;
            if attempts < 3 {
                Err(PortError::WriterBusy("injected short reservation".into()))
            } else {
                SharedGuard::try_acquire(root.path(), LockKind::PolicyEmission)
            }
        })
        .unwrap();
        assert_eq!(attempts, 3);
        assert!(Instant::now() < deadline);
        drop(held);
        let exclusive = ExclusiveGuard::try_acquire(root.path(), LockKind::PolicyEmission).unwrap();
        let start = Instant::now();
        let bounded_deadline = start + Duration::from_millis(20);
        let mut real_attempts = 0;
        let failure = emission_admission(bounded_deadline, || {
            real_attempts += 1;
            SharedGuard::try_acquire(root.path(), LockKind::PolicyEmission)
        })
        .err()
        .unwrap();
        assert!(matches!(
            failure,
            CacheError::Unavailable(CacheUnavailable::Busy | CacheUnavailable::Deadline)
        ));
        assert!(real_attempts > 0);
        // Do not turn OS scheduling delay into a product timing assertion.
        // The request-relative cap is proven by refusing to return success
        // before the caller's deadline while the real exclusive lock is held.
        assert!(Instant::now() >= bounded_deadline);
        drop(exclusive);
        assert!(
            emission_admission(Instant::now(), || panic!(
                "expired request attempted a lock"
            ))
            .is_err()
        );
    }
}
