//! Verified per-source evidence inside the catalog. Callers own writer leases,
//! current control authorization, source verification and the outer transaction.
//! This module never opens a source, commits the outer transaction, or reads
//! legacy merged payload/index tables as evidence.
//!
//! Integration order: enable foreign_keys before the outer transaction; add
//! the three store_metadata columns and create_schema during v20 migration;
//! initialize_catalog_in_tx only during explicit managed activation. Publish
//! source-specific batches before cross-source payload merging, collect their
//! minimum generations, perform the existing batch CAS, then call
//! finalize_publications_in_tx with every publication before COMMIT. A legacy
//! no-op shortcut must still record the managed observation/publication.
//!
//! Reads need a dedicated connection, a current control-verified ReadScope,
//! CatalogHandles lifetime ownership and a separate emission policy recheck.
//! This foundation implements full replacement, not verified append/delta,
//! semantic jobs, restore or all-surface routing. Discovery publication is a
//! separate writer seam; latest proof is read in this snapshot. Replaced
//! document/occurrence facts conservatively advance the destructive epoch.

use crate::{SourceBatch, safe_fts_query, stored_activity_from, usage_id_for};
use agent_session_grep_application::{bounded_index_text, fts_tokens_cjk, parse_search_instant};
use agent_session_grep_domain::{
    IdKind, Message, Role, Session, SessionContextGraph, SourceDocument, StableId,
};
use agent_session_grep_ports::{PortError, PortResult, SidechainFacet, control, managed::*};
use rusqlite::{Connection, OptionalExtension, Transaction, ffi, params, types::Value};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::{
    collections::{BTreeMap, BTreeSet},
    time::Instant,
};

fn invalid() -> PortError {
    PortError::InvalidRequest("invalid managed projection operation".into())
}
fn corrupt() -> PortError {
    PortError::SchemaIncompatible("managed projection state unavailable".into())
}
fn timeout() -> PortError {
    PortError::WriterBusy("managed projection deadline exceeded".into())
}
fn sql(error: rusqlite::Error) -> PortError {
    match error.sqlite_error_code() {
        Some(rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked) => {
            PortError::WriterBusy("managed projection storage is busy".into())
        }
        Some(rusqlite::ErrorCode::OperationInterrupted) => timeout(),
        _ => corrupt(),
    }
}
fn encode(value: &impl Serialize) -> PortResult<Vec<u8>> {
    serde_json::to_vec(value).map_err(|_| invalid())
}
fn decode<T: DeserializeOwned>(bytes: &[u8]) -> PortResult<T> {
    serde_json::from_slice(bytes).map_err(|_| corrupt())
}
fn digest(fields: &[&[u8]]) -> String {
    let mut hash = blake3::Hasher::new();
    hash.update(b"managed-projection-v1");
    for field in fields {
        hash.update(&(field.len() as u64).to_le_bytes());
        hash.update(field);
    }
    hash.finalize().to_hex().to_string()
}
fn checked_label(value: &str) -> PortResult<()> {
    if value.is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
        Err(invalid())
    } else {
        Ok(())
    }
}
struct RankedMetadataRow {
    rowid: i64,
    score: f64,
    tie: (String, String, String, String),
}
struct MetadataRow {
    payload: Vec<u8>,
    payload_digest: String,
    source: String,
    projection: String,
    revision: String,
    search_text: String,
    search_digest: String,
}
fn scoped_bm25(count: i64, total: i64, dfs: &[f64], stats: &[u32]) -> PortResult<f64> {
    if count <= 0
        || total <= 0
        || stats.len() != dfs.len() + 1
        || dfs
            .iter()
            .any(|df| !df.is_finite() || *df < 0.0 || *df > count as f64)
    {
        return Err(corrupt());
    }
    let norm = 0.25 + 0.75 * f64::from(stats[0]) / (total as f64 / count as f64);
    let score = dfs
        .iter()
        .zip(&stats[1..])
        .map(|(df, tf)| {
            let tf = f64::from(*tf);
            let idf = (1.0 + (count as f64 - df + 0.5) / (df + 0.5)).ln();
            idf * tf * 2.2 / (tf + 1.2 * norm)
        })
        .sum::<f64>();
    if !score.is_finite() {
        Err(corrupt())
    } else {
        Ok(score)
    }
}
fn in_transaction(conn: &Connection) -> PortResult<()> {
    let foreign_keys: bool = conn
        .query_row("PRAGMA foreign_keys", [], |row| row.get(0))
        .map_err(sql)?;
    if conn.is_autocommit() || !foreign_keys {
        Err(invalid())
    } else {
        Ok(())
    }
}

/// Additive schema body for the caller's v19 -> v20 transaction. The caller
/// adds store_metadata.{projection_contract_version,managed_mode,destructive_epoch}
/// and sets user_version=20. There is no legacy evidence backfill.
pub fn create_schema(conn: &Connection) -> PortResult<()> {
    in_transaction(conn)?;
    conn.execute_batch(SCHEMA).map_err(sql)?;
    create_retained_receipt_schema(conn)?;
    crate::managed_source_context::create_schema(conn)
}

/// Additive v21 proof for exact historical receipts retained by an authorized
/// recovery. Empty on migration: no foreign receipt is grandfathered in.
pub(crate) fn create_retained_receipt_schema(conn: &Connection) -> PortResult<()> {
    in_transaction(conn)?;
    conn.execute_batch("CREATE TABLE IF NOT EXISTS retained_source_receipts(
        revision_id TEXT PRIMARY KEY REFERENCES source_revision_receipts(revision_id) ON DELETE CASCADE,
        retained_incarnation TEXT NOT NULL, original_incarnation TEXT NOT NULL,
        revision_digest TEXT NOT NULL, committed_generation INTEGER NOT NULL CHECK(committed_generation>=0),
        operation_id TEXT NOT NULL);").map_err(sql)
}

/// Called only inside verified recovery's catalog transaction. Preserve exact
/// old projection provenance without rewriting observation time/token fields.
pub(crate) fn retain_receipts_after_recovery(
    conn: &Connection,
    original: &str,
    recovery: &str,
    operation: &str,
) -> PortResult<()> {
    in_transaction(conn)?;
    for value in [original, recovery, operation] {
        control::ControlId::parse(value).map_err(|_| invalid())?;
    }
    if original == recovery {
        return Err(invalid());
    }
    let actual: String = conn
        .query_row(
            "SELECT catalog_incarnation FROM catalog_meta WHERE singleton=1",
            [],
            |r| r.get(0),
        )
        .map_err(sql)?;
    if actual != original {
        return Err(corrupt());
    }
    let unknown:bool=conn.query_row("SELECT EXISTS(SELECT 1 FROM source_revision_receipts r WHERE r.published=1 AND r.catalog_incarnation!=?1 AND NOT EXISTS(SELECT 1 FROM retained_source_receipts p WHERE p.revision_id=r.revision_id AND p.retained_incarnation=?1 AND p.original_incarnation=r.catalog_incarnation AND p.revision_digest=r.revision_digest AND p.committed_generation=r.committed_generation))",[original],|r|r.get(0)).map_err(sql)?;
    if unknown {
        return Err(corrupt());
    }
    conn.execute("UPDATE retained_source_receipts SET retained_incarnation=?1,operation_id=?2 WHERE retained_incarnation=?3",params![recovery,operation,original]).map_err(sql)?;
    conn.execute("INSERT INTO retained_source_receipts(revision_id,retained_incarnation,original_incarnation,revision_digest,committed_generation,operation_id) SELECT revision_id,?1,catalog_incarnation,revision_digest,committed_generation,?2 FROM source_revision_receipts WHERE published=1 AND catalog_incarnation=?3 ON CONFLICT(revision_id) DO UPDATE SET retained_incarnation=excluded.retained_incarnation,original_incarnation=excluded.original_incarnation,revision_digest=excluded.revision_digest,committed_generation=excluded.committed_generation,operation_id=excluded.operation_id",params![recovery,operation,original]).map_err(sql)?;
    Ok(())
}

const SCHEMA: &str = r"
CREATE TABLE catalog_meta(singleton INTEGER PRIMARY KEY CHECK(singleton=1), installation_id TEXT NOT NULL, catalog_incarnation TEXT NOT NULL, created_at_ms INTEGER NOT NULL);
CREATE TABLE source_bindings(source_id TEXT PRIMARY KEY, source_path TEXT NOT NULL UNIQUE, provider_id TEXT NOT NULL, namespace_id TEXT, root_identity TEXT NOT NULL, bound_at_ms INTEGER NOT NULL);
CREATE TABLE source_heads(source_id TEXT PRIMARY KEY REFERENCES source_bindings(source_id), visible_revision_id TEXT, latest_receipt_id TEXT, content_set_digest TEXT, last_attempt_id TEXT, update_state TEXT NOT NULL CHECK(update_state IN ('unknown','current','partial','failed','deferred','paused','revoked')), observed_cycle_seq INTEGER);
CREATE TABLE source_revision_receipts(revision_id TEXT PRIMARY KEY, source_id TEXT NOT NULL REFERENCES source_bindings(source_id), revision_seq INTEGER NOT NULL CHECK(revision_seq>=1), revision_digest TEXT NOT NULL, parser_version INTEGER NOT NULL, completeness TEXT NOT NULL CHECK(completeness IN ('complete','append','partial')), published INTEGER NOT NULL CHECK(published IN (0,1)), cycle_seq INTEGER NOT NULL, worker_boot_id TEXT NOT NULL, catalog_incarnation TEXT NOT NULL, policy_epoch INTEGER NOT NULL, started_control_seq INTEGER NOT NULL, content_revision_id TEXT, content_set_digest TEXT, committed_generation INTEGER, observed_at_ms INTEGER NOT NULL, committed_at_ms INTEGER, reason TEXT, UNIQUE(source_id,revision_seq), CHECK(published=(completeness IN ('complete','append'))), CHECK(published=0 OR (committed_generation IS NOT NULL AND committed_at_ms IS NOT NULL)));
CREATE INDEX source_receipts_digest ON source_revision_receipts(source_id,revision_digest);
CREATE TABLE receipt_selection_claims(revision_id TEXT NOT NULL REFERENCES source_revision_receipts(revision_id), selection_id TEXT NOT NULL, selection_revision INTEGER NOT NULL, root_identity TEXT NOT NULL, PRIMARY KEY(revision_id,selection_id));
CREATE TABLE discovery_receipts(cycle_seq INTEGER NOT NULL, selection_id TEXT NOT NULL, selection_revision INTEGER NOT NULL, worker_boot_id TEXT NOT NULL, policy_epoch INTEGER NOT NULL, started_control_seq INTEGER NOT NULL, catalog_incarnation TEXT NOT NULL, root_identity TEXT NOT NULL, source_set_digest TEXT NOT NULL, complete INTEGER NOT NULL CHECK(complete IN (0,1)), committed_generation INTEGER NOT NULL, PRIMARY KEY(cycle_seq,selection_id));
CREATE TABLE discovery_sources(cycle_seq INTEGER NOT NULL, selection_id TEXT NOT NULL, source_id TEXT NOT NULL, revision_id TEXT NOT NULL REFERENCES source_revision_receipts(revision_id), PRIMARY KEY(cycle_seq,selection_id,source_id), FOREIGN KEY(cycle_seq,selection_id) REFERENCES discovery_receipts(cycle_seq,selection_id));
CREATE TABLE source_scope_claims(source_id TEXT NOT NULL, selection_id TEXT NOT NULL, selection_revision INTEGER NOT NULL, policy_epoch INTEGER NOT NULL, validated_at_ms INTEGER NOT NULL, PRIMARY KEY(source_id,selection_id));
CREATE TABLE source_projections(projection_rowid INTEGER PRIMARY KEY, projection_id TEXT NOT NULL UNIQUE, source_id TEXT NOT NULL REFERENCES source_bindings(source_id), revision_id TEXT NOT NULL REFERENCES source_revision_receipts(revision_id), message_id TEXT NOT NULL, payload BLOB NOT NULL, payload_digest TEXT NOT NULL, index_text TEXT NOT NULL, index_digest TEXT NOT NULL, fts_text TEXT NOT NULL, UNIQUE(source_id,message_id));
CREATE INDEX source_projections_message ON source_projections(message_id,source_id);
CREATE TABLE source_occurrences(occurrence_rowid INTEGER PRIMARY KEY, source_id TEXT NOT NULL REFERENCES source_bindings(source_id), revision_id TEXT NOT NULL REFERENCES source_revision_receipts(revision_id), message_id TEXT NOT NULL, session_id TEXT NOT NULL, document_id TEXT NOT NULL, placement_id TEXT NOT NULL, provider_id TEXT NOT NULL, project_id TEXT, instant_unix_seconds INTEGER, instant_nanosecond INTEGER, role TEXT NOT NULL, is_sidechain INTEGER NOT NULL CHECK(is_sidechain IN (0,1)), byte_start INTEGER, byte_end INTEGER, source_ordinal INTEGER NOT NULL CHECK(source_ordinal>=0), precision TEXT NOT NULL, payload BLOB NOT NULL, payload_digest TEXT NOT NULL, CHECK((byte_start IS NULL AND byte_end IS NULL) OR (byte_start>=0 AND byte_end>=byte_start)), UNIQUE(source_id,placement_id));
CREATE INDEX source_occurrences_message ON source_occurrences(message_id,source_id);
CREATE INDEX source_occurrences_filter ON source_occurrences(provider_id,project_id,instant_unix_seconds);
CREATE TABLE source_entity_projections(entity_projection_rowid INTEGER PRIMARY KEY, projection_id TEXT NOT NULL UNIQUE, source_id TEXT NOT NULL REFERENCES source_bindings(source_id), revision_id TEXT NOT NULL REFERENCES source_revision_receipts(revision_id), kind TEXT NOT NULL CHECK(kind IN ('session','document','edge','tool_activity','usage_event','session_title','repo_identity','resume_claim')), entity_key TEXT NOT NULL, entity_id TEXT NOT NULL, parent_id TEXT, payload BLOB NOT NULL, payload_digest TEXT NOT NULL, UNIQUE(source_id,kind,entity_key));
CREATE INDEX source_entity_projections_entity ON source_entity_projections(entity_id,kind,source_id);
CREATE TABLE source_session_projections(session_projection_rowid INTEGER PRIMARY KEY, source_id TEXT NOT NULL REFERENCES source_bindings(source_id), revision_id TEXT NOT NULL REFERENCES source_revision_receipts(revision_id), session_id TEXT NOT NULL, title TEXT, search_text TEXT NOT NULL, search_digest TEXT NOT NULL, fts_text TEXT NOT NULL, repo_slug TEXT, UNIQUE(source_id,session_id));
CREATE INDEX source_session_projections_session ON source_session_projections(session_id);
CREATE VIRTUAL TABLE projection_fts USING fts5(fts_text, content='source_projections', content_rowid='projection_rowid', tokenize='unicode61');
CREATE VIRTUAL TABLE session_metadata_fts USING fts5(fts_text, content='source_session_projections', content_rowid='session_projection_rowid', tokenize='unicode61');
CREATE TABLE projection_fts_stats(projection_rowid INTEGER PRIMARY KEY REFERENCES source_projections(projection_rowid) ON DELETE CASCADE, token_count INTEGER NOT NULL CHECK(token_count>=0), index_digest TEXT NOT NULL);
CREATE TABLE session_fts_stats(session_projection_rowid INTEGER PRIMARY KEY REFERENCES source_session_projections(session_projection_rowid) ON DELETE CASCADE, token_count INTEGER NOT NULL CHECK(token_count>=0), search_digest TEXT NOT NULL);
CREATE TRIGGER projection_insert AFTER INSERT ON source_projections BEGIN INSERT INTO projection_fts(rowid,fts_text) VALUES(new.projection_rowid,new.fts_text); END;
CREATE TRIGGER projection_delete AFTER DELETE ON source_projections BEGIN INSERT INTO projection_fts(projection_fts,rowid,fts_text) VALUES('delete',old.projection_rowid,old.fts_text); END;
CREATE TRIGGER projection_update AFTER UPDATE OF fts_text ON source_projections BEGIN INSERT INTO projection_fts(projection_fts,rowid,fts_text) VALUES('delete',old.projection_rowid,old.fts_text); INSERT INTO projection_fts(rowid,fts_text) VALUES(new.projection_rowid,new.fts_text); END;
CREATE TRIGGER session_projection_insert AFTER INSERT ON source_session_projections BEGIN INSERT INTO session_metadata_fts(rowid,fts_text) VALUES(new.session_projection_rowid,new.fts_text); END;
CREATE TRIGGER session_projection_delete AFTER DELETE ON source_session_projections BEGIN INSERT INTO session_metadata_fts(session_metadata_fts,rowid,fts_text) VALUES('delete',old.session_projection_rowid,old.fts_text); END;
CREATE TRIGGER session_projection_update AFTER UPDATE OF fts_text ON source_session_projections BEGIN INSERT INTO session_metadata_fts(session_metadata_fts,rowid,fts_text) VALUES('delete',old.session_projection_rowid,old.fts_text); INSERT INTO session_metadata_fts(rowid,fts_text) VALUES(new.session_projection_rowid,new.fts_text); END;
";

pub fn initialize_catalog_in_tx(
    conn: &Connection,
    installation: &str,
    incarnation: &str,
    now_ms: i64,
) -> PortResult<()> {
    in_transaction(conn)?;
    checked_label(installation)?;
    checked_label(incarnation)?;
    if now_ms < 0 {
        return Err(invalid());
    }
    conn.execute(
        "INSERT INTO catalog_meta VALUES(1,?1,?2,?3)",
        params![installation, incarnation, now_ms],
    )
    .map_err(sql)?;
    conn.execute(
        "UPDATE store_metadata SET projection_contract_version=1,managed_mode=1 WHERE singleton=1",
        [],
    )
    .map_err(sql)?;
    Ok(())
}

/// Explicit first activation of an owned logical legacy copy. This shares the
/// normative schema body with ordinary v20 migration, but records activation in
/// the same transaction. It never derives source permission from merged rows.
pub(crate) fn activate_legacy_copy_in_tx(
    conn: &Connection,
    installation: &str,
    incarnation: &str,
    now_ms: i64,
) -> PortResult<()> {
    in_transaction(conn)?;
    let version: i64 = conn
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(sql)?;
    if version != 19 {
        return Err(corrupt());
    }
    conn.execute_batch(
        "ALTER TABLE store_metadata ADD COLUMN projection_contract_version INTEGER NOT NULL DEFAULT 0;
         ALTER TABLE store_metadata ADD COLUMN managed_mode INTEGER NOT NULL DEFAULT 0 CHECK(managed_mode IN (0,1));
         ALTER TABLE store_metadata ADD COLUMN destructive_epoch INTEGER NOT NULL DEFAULT 0;",
    ).map_err(sql)?;
    create_schema(conn)?;
    initialize_catalog_in_tx(conn, installation, incarnation, now_ms)?;
    conn.pragma_update(None, "application_id", crate::managed_store::APPLICATION_ID)
        .map_err(sql)?;
    conn.pragma_update(None, "user_version", crate::SCHEMA_VERSION)
        .map_err(sql)?;
    Ok(())
}

#[derive(Deserialize)]
struct InputMessage {
    role: Role,
    text: String,
    timestamp: Option<String>,
}
#[derive(Deserialize)]
struct InputDocument {
    provider: String,
    variant: String,
    fingerprint: String,
    len: u64,
}
#[derive(Default, Deserialize)]
struct InputSession {
    #[serde(default)]
    documents: Vec<String>,
    document: Option<String>,
    title: Option<String>,
    summary: Option<String>,
}
struct Prepared {
    messages: BTreeMap<String, Message>,
    occurrences: BTreeMap<String, OccurrenceData>,
    entities: BTreeMap<(String, String), (String, Option<String>, EntityData)>,
}
impl Prepared {
    /// Register one keyed entity. Tool activity and usage keys are content
    /// addressed, so an identical repeat (two equal tool calls in one turn,
    /// two turns with equal incremental token buckets) is the same fact
    /// observed twice and folds into one row, matching the legacy writer. A
    /// different value under the same key is still a conflict and rejects
    /// the whole source; every other entity kind must be unique.
    fn entity(
        &mut self,
        kind: EntityKind,
        key: String,
        id: &StableId,
        parent: Option<String>,
        data: EntityData,
    ) -> PortResult<()> {
        let value = (id.as_str().to_owned(), parent, data);
        match self.entities.entry((kind.as_str().into(), key)) {
            std::collections::btree_map::Entry::Vacant(slot) => {
                slot.insert(value);
                Ok(())
            }
            std::collections::btree_map::Entry::Occupied(existing)
                if matches!(kind, EntityKind::Tool | EntityKind::Usage)
                    && existing.get() == &value =>
            {
                Ok(())
            }
            std::collections::btree_map::Entry::Occupied(_) => Err(invalid()),
        }
    }
    fn fingerprints(&self) -> PortResult<BTreeMap<String, String>> {
        let mut rows = BTreeMap::new();
        for (key, value) in &self.messages {
            rows.insert(format!("m:{key}"), digest(&[&encode(value)?]));
        }
        for (key, value) in &self.occurrences {
            rows.insert(format!("o:{key}"), digest(&[&encode(value)?]));
        }
        for ((kind, key), (_, _, value)) in &self.entities {
            rows.insert(format!("e:{kind}:{key}"), digest(&[&encode(value)?]));
        }
        Ok(rows)
    }
}

fn prepare(batch: &SourceBatch, observation: &SourceObservation) -> PortResult<Prepared> {
    let mut output = Prepared {
        messages: BTreeMap::new(),
        occurrences: BTreeMap::new(),
        entities: BTreeMap::new(),
    };
    let mut sessions = BTreeMap::new();
    let mut documents = BTreeMap::new();
    let mut identities = BTreeMap::new();
    for (id, bytes, _) in &batch.entries {
        if !id.validate()
            || identities
                .insert(id.as_str().to_owned(), id.clone())
                .is_some()
        {
            return Err(invalid());
        }
        match id.kind() {
            IdKind::Message => {
                let input: InputMessage = decode(bytes).map_err(|_| invalid())?;
                output.messages.insert(
                    id.as_str().into(),
                    Message {
                        id: id.clone(),
                        role: input.role,
                        text: input.text,
                        timestamp: input.timestamp,
                    },
                );
            }
            IdKind::Session => {
                sessions.insert(
                    id.as_str().to_owned(),
                    (
                        id.clone(),
                        decode::<InputSession>(bytes).map_err(|_| invalid())?,
                    ),
                );
            }
            IdKind::Document => {
                let input: InputDocument = decode(bytes).map_err(|_| invalid())?;
                if input.provider != observation.binding.provider.as_str()
                    || input.fingerprint != observation.revision_digest
                    || i64::try_from(input.len).ok() != batch.len_bytes
                {
                    return Err(invalid());
                }
                let doc = SourceDocument {
                    id: id.clone(),
                    provider_id: input.provider,
                    variant_id: input.variant,
                    fingerprint: input.fingerprint,
                    len: input.len,
                };
                doc.validate().map_err(|_| invalid())?;
                documents.insert(id.as_str().to_owned(), doc.clone());
                output.entity(
                    EntityKind::Document,
                    id.as_str().into(),
                    id,
                    None,
                    EntityData::Document(doc),
                )?;
            }
            _ => return Err(invalid()),
        }
    }
    let mut repos = BTreeMap::new();
    for repo in &observation.repositories {
        if !sessions.contains_key(repo.session_id.as_str())
            || repo.slug.is_empty()
            || repo.slug.len() > 512
            || repo
                .slug
                .chars()
                .any(|c| c.is_control() || c.is_whitespace())
            || repo.slug.contains(['\\', ':'])
            || repo.slug.starts_with('/')
            || repos
                .insert(repo.session_id.as_str().to_owned(), repo.slug.clone())
                .is_some()
        {
            return Err(invalid());
        }
        let pair = batch.resume_claims.iter().any(|c| {
            c.session_id == repo.session_id.as_str()
                && c.pair_observed
                && c.provider_session_id_state == "resolved"
                && c.original_working_directory_state == "resolved"
        });
        if !pair {
            return Err(invalid());
        }
        output.entity(
            EntityKind::Repository,
            repo.session_id.as_str().into(),
            &repo.session_id,
            None,
            EntityData::Repository(repo.clone()),
        )?;
    }
    for (wire, (id, input)) in &sessions {
        let placements: Vec<_> = batch
            .placements
            .iter()
            .filter(|p| p.session_id == *id)
            .cloned()
            .collect();
        let children: BTreeSet<_> = placements.iter().map(|p| p.id.as_str()).collect();
        let graph = SessionContextGraph {
            session_id: id.clone(),
            messages: output.messages.values().cloned().collect(),
            source_documents: documents.values().cloned().collect(),
            placements: placements.clone(),
            edges: batch
                .edges
                .iter()
                .filter(|e| children.contains(e.child_placement_id.as_str()))
                .cloned()
                .collect(),
        };
        graph.validate().map_err(|_| invalid())?;
        let mut doc_ids: BTreeSet<_> = input
            .documents
            .iter()
            .cloned()
            .chain(input.document.iter().cloned())
            .collect();
        doc_ids.extend(
            placements
                .iter()
                .map(|p| p.source_document_id.as_str().to_owned()),
        );
        let docs = doc_ids
            .iter()
            .map(|d| documents.get(d).map(|d| d.id.clone()).ok_or_else(invalid))
            .collect::<PortResult<Vec<_>>>()?;
        let first = placements
            .iter()
            .filter_map(|p| {
                output
                    .messages
                    .get(p.message_id.as_str())
                    .filter(|m| m.role == Role::User)
                    .map(|m| (p.source_ordinal, m.text.as_str()))
            })
            .min_by_key(|(ordinal, _)| *ordinal)
            .map(|(_, text)| text);
        let title = input
            .title
            .as_deref()
            .filter(|s| !s.trim().is_empty())
            .or(input.summary.as_deref().filter(|s| !s.trim().is_empty()))
            .or(first)
            .map(|s| {
                s.trim()
                    .chars()
                    .take(crate::SESSION_TITLE_MAX_CHARS)
                    .collect()
            });
        output.entity(
            EntityKind::Session,
            wire.clone(),
            id,
            None,
            EntityData::Session(SessionData {
                session: Session { id: id.clone() },
                documents: docs,
                title,
                repo_slug: repos.get(wire).cloned(),
                provider_id: observation.binding.provider.as_str().into(),
                first_user_text: first
                    .map(|s| s.chars().take(crate::SESSION_SEARCH_FIELD_CHARS).collect()),
            }),
        )?;
    }
    for p in &batch.placements {
        if !sessions.contains_key(p.session_id.as_str()) {
            return Err(invalid());
        }
        let message = output
            .messages
            .get(p.message_id.as_str())
            .ok_or_else(invalid)?;
        let data = OccurrenceData {
            placement: p.clone(),
            provider_id: observation.binding.provider.as_str().into(),
            project_id: repos.get(p.session_id.as_str()).cloned(),
            timestamp: message.timestamp.clone(),
            role: message.role,
        };
        if output
            .occurrences
            .insert(p.id.as_str().into(), data)
            .is_some()
        {
            return Err(invalid());
        }
    }
    if output.messages.keys().any(|id| {
        !output
            .occurrences
            .values()
            .any(|o| o.placement.message_id.as_str() == id)
    }) {
        return Err(invalid());
    }
    for edge in &batch.edges {
        let child = output
            .occurrences
            .get(edge.child_placement_id.as_str())
            .ok_or_else(invalid)?;
        let child_id = child.placement.message_id.clone();
        output.entity(
            EntityKind::Edge,
            edge.child_placement_id.as_str().into(),
            &child_id,
            Some(edge.parent_message_id.as_str().into()),
            EntityData::Edge {
                child: edge.child_placement_id.clone(),
                parent: edge.parent_message_id.clone(),
                relation: edge.relation,
            },
        )?;
    }
    for activity in &batch.activities {
        if !output.messages.contains_key(activity.message_id.as_str()) {
            return Err(invalid());
        }
        let normalized = stored_activity_from(&activity.message_id, &activity.activity)
            .map_err(|_| invalid())?;
        let mut data = activity.activity.clone();
        data.name = normalized.name;
        data.target = normalized.target;
        output.entity(
            EntityKind::Tool,
            normalized.activity_id.clone(),
            &activity.message_id,
            None,
            EntityData::Tool {
                activity_id: normalized.activity_id,
                message_id: activity.message_id.clone(),
                activity: data,
            },
        )?;
    }
    for event in &batch.usage_events {
        if !sessions.contains_key(event.session_id.as_str())
            || event
                .message_id
                .as_ref()
                .is_some_and(|m| !output.messages.contains_key(m.as_str()))
        {
            return Err(invalid());
        }
        let key = usage_id_for(
            event.session_id.as_str(),
            event.message_id.as_ref().map(StableId::as_str),
            &event.usage,
        );
        output.entity(
            EntityKind::Usage,
            key.clone(),
            &event.session_id,
            event.message_id.as_ref().map(|m| m.as_str().into()),
            EntityData::Usage {
                usage_id: key,
                session_id: event.session_id.clone(),
                message_id: event.message_id.clone(),
                usage: event.usage.clone(),
            },
        )?;
    }
    for claim in &batch.resume_claims {
        let id = identities
            .get(&claim.session_id)
            .filter(|id| id.kind() == IdKind::Session)
            .ok_or_else(invalid)?;
        if claim.provider_id != observation.binding.provider.as_str() {
            return Err(invalid());
        }
        let decode_value = |state: &str, value: &Option<String>| match (state, value) {
            ("missing", None) => Ok(ResumeValue::Missing),
            ("ambiguous", None) => Ok(ResumeValue::Ambiguous),
            ("resolved", Some(value)) if !value.trim().is_empty() => {
                Ok(ResumeValue::Resolved(value.clone()))
            }
            _ => Err(invalid()),
        };
        let native = decode_value(&claim.provider_session_id_state, &claim.provider_session_id)?;
        let cwd = decode_value(
            &claim.original_working_directory_state,
            &claim.original_working_directory,
        )?;
        output.entity(
            EntityKind::Resume,
            claim.session_id.clone(),
            id,
            None,
            EntityData::Resume(ResumeData {
                session_id: id.clone(),
                provider_id: claim.provider_id.clone(),
                provider_session_id: native,
                original_working_directory: if claim.pair_observed {
                    cwd
                } else {
                    ResumeValue::Missing
                },
                pair_observed: claim.pair_observed,
            }),
        )?;
    }
    Ok(output)
}

/// All writes are protected by a nested savepoint, so an error cannot leave a
/// partial projection set even if the outer caller handles it and continues.
/// target_generation is the caller's planned CAS generation (base or base+1).
pub fn publish_source_in_tx(
    conn: &Connection,
    batch: &SourceBatch,
    observation: &SourceObservation,
    target_generation: i64,
) -> PortResult<Publication> {
    crate::managed_source_context::legacy_publication_allowed(
        conn,
        observation.binding.source_id.as_str(),
    )?;
    publish_source_uncontextualized_in_tx(conn, batch, observation, target_generation)
}

pub(crate) fn publish_source_uncontextualized_in_tx(
    conn: &Connection,
    batch: &SourceBatch,
    observation: &SourceObservation,
    target_generation: i64,
) -> PortResult<Publication> {
    in_transaction(conn)?;
    conn.execute_batch("SAVEPOINT managed_publication")
        .map_err(sql)?;
    struct Rollback<'a>(&'a Connection, bool);
    impl Drop for Rollback<'_> {
        fn drop(&mut self) {
            if self.1 {
                let _ = self
                    .0
                    .execute_batch("ROLLBACK TO managed_publication; RELEASE managed_publication");
            }
        }
    }
    let mut rollback = Rollback(conn, true);
    let result = publication_savepoint(conn, batch, observation, target_generation);
    if result.is_ok() {
        conn.execute_batch("RELEASE managed_publication")
            .map_err(sql)?;
        rollback.1 = false;
    }
    result
}

fn publication_savepoint(
    conn: &Connection,
    batch: &SourceBatch,
    o: &SourceObservation,
    target: i64,
) -> PortResult<Publication> {
    checked_label(&o.binding.root_identity)?;
    checked_label(&o.revision_digest)?;
    checked_label(&o.worker_boot_id)?;
    if o.binding.source_path != batch.source_path
        || o.binding.source_path.is_empty()
        || o.parser_version == 0
        || o.selections.is_empty()
        || batch
            .provider_id
            .as_deref()
            .is_some_and(|p| p != o.binding.provider.as_str())
        || [
            o.cycle_seq,
            o.policy_epoch,
            o.started_control_seq,
            o.observed_at_ms,
            o.committed_at_ms,
        ]
        .iter()
        .any(|n| *n < 0)
    {
        return Err(invalid());
    }
    let (incarnation,base,epoch):(String,i64,i64)=conn.query_row("SELECT catalog_incarnation,active_generation,destructive_epoch FROM catalog_meta CROSS JOIN store_metadata WHERE catalog_meta.singleton=1 AND store_metadata.singleton=1 AND managed_mode=1 AND projection_contract_version=1",[],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).map_err(sql)?;
    if incarnation != o.catalog_incarnation
        || target < base
        || target > base.checked_add(1).ok_or_else(invalid)?
    {
        return Err(invalid());
    }
    register_fts(conn)?;
    let b = &o.binding;
    conn.execute(
        "INSERT OR IGNORE INTO source_bindings VALUES(?1,?2,?3,?4,?5,?6)",
        params![
            b.source_id.as_str(),
            b.source_path,
            b.provider.as_str(),
            b.namespace_id,
            b.root_identity,
            o.observed_at_ms
        ],
    )
    .map_err(sql)?;
    validate_binding(conn, b)?;
    conn.execute(
        "INSERT OR IGNORE INTO source_heads(source_id,update_state) VALUES(?1,'unknown')",
        [b.source_id.as_str()],
    )
    .map_err(sql)?;
    let reason = match o.state {
        ObservationState::Complete if !batch.relation_complete => Some("incomplete"),
        ObservationState::Complete
            if batch.fingerprint.as_deref() != Some(&o.revision_digest)
                || batch.len_bytes.is_none_or(|n| n < 0) =>
        {
            Some("unstable")
        }
        ObservationState::Complete => None,
        ObservationState::Incomplete => Some("incomplete"),
        ObservationState::Unstable => Some("unstable"),
        ObservationState::RewritePending => Some("rewrite_pending"),
        ObservationState::DeletionPending => Some("deletion_pending"),
    };
    let prepared = if reason.is_none() {
        Some(prepare(batch, o)?)
    } else {
        None
    };
    let old = stored_fingerprints(conn, b.source_id.as_str())?;
    let new = prepared.as_ref().map(Prepared::fingerprints).transpose()?;
    let changed = new.as_ref().is_some_and(|new| *new != old);
    let destructive = new
        .as_ref()
        .is_some_and(|new| old.iter().any(|(k, v)| new.get(k) != Some(v)));
    if changed && target == base {
        return Err(invalid());
    }
    let digest_value = new
        .as_ref()
        .map(|rows| encode(rows).map(|v| digest(&[&v])))
        .transpose()?;
    let old_revision: Option<String> = conn
        .query_row(
            "SELECT visible_revision_id FROM source_heads WHERE source_id=?1",
            [b.source_id.as_str()],
            |r| r.get(0),
        )
        .map_err(sql)?;
    let rebind_retained = if reason.is_none() {
        let mut statement = conn.prepare("SELECT revision_id FROM source_projections WHERE source_id=?1
            UNION SELECT revision_id FROM source_occurrences WHERE source_id=?1
            UNION SELECT revision_id FROM source_entity_projections WHERE source_id=?1
            UNION SELECT revision_id FROM source_session_projections WHERE source_id=?1
            UNION SELECT visible_revision_id FROM source_heads WHERE source_id=?1 AND visible_revision_id IS NOT NULL").map_err(sql)?;
        let mut rows = statement.query([b.source_id.as_str()]).map_err(sql)?;
        let mut retained = false;
        while let Some(row) = rows.next().map_err(sql)? {
            let id: String = row.get(0).map_err(sql)?;
            let receipt =
                crate::managed_receipt::read_checked(conn, &id, Some(b.source_id.as_str()))?;
            if !receipt.published
                || receipt
                    .committed_generation
                    .is_none_or(|generation| generation > base)
            {
                return Err(corrupt());
            }
            if receipt.catalog_incarnation != incarnation {
                if !retained_receipt_matches(conn, &receipt, &incarnation, base)? {
                    return Err(corrupt());
                }
                retained = true;
            }
        }
        retained
    } else {
        false
    };
    let content_revision =
        if reason.is_none() && (changed || rebind_retained || old_revision.is_none()) {
            Some(o.revision_id.as_str().to_owned())
        } else {
            old_revision
        };
    let seq:i64=conn.query_row("SELECT COALESCE(MAX(revision_seq),0)+1 FROM source_revision_receipts WHERE source_id=?1",[b.source_id.as_str()],|r|r.get(0)).map_err(sql)?;
    let published = reason.is_none();
    let committed_generation = if changed { target } else { base };
    conn.execute("INSERT INTO source_revision_receipts VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18)",params![o.revision_id.as_str(),b.source_id.as_str(),seq,o.revision_digest,o.parser_version,if published{"complete"}else{"partial"},published,o.cycle_seq,o.worker_boot_id,o.catalog_incarnation,o.policy_epoch,o.started_control_seq,content_revision,digest_value,published.then_some(committed_generation),o.observed_at_ms,published.then_some(o.committed_at_ms),reason]).map_err(sql)?;
    for selection in &o.selections {
        checked_label(&selection.selection_id)?;
        checked_label(&selection.root_identity)?;
        // Each proof carries the root actually verified for that selection. The
        // binding root stays historical evidence for overlapping parent/child
        // roots; it is not an equality requirement for every participating
        // selection. authorize_observation binds every proof to current control.
        if selection.selection_revision < 0 {
            return Err(invalid());
        }
        conn.execute(
            "INSERT INTO receipt_selection_claims VALUES(?1,?2,?3,?4)",
            params![
                o.revision_id.as_str(),
                selection.selection_id,
                selection.selection_revision,
                selection.root_identity
            ],
        )
        .map_err(sql)?;
    }
    if let Some(prepared) = prepared {
        if changed {
            write_prepared(
                conn,
                b.source_id.as_str(),
                o.revision_id.as_str(),
                &prepared,
            )?;
        }
        if rebind_retained {
            // A complete new observation verifies every surviving projection.
            // Rebind provenance only: stable rows/ids/text and content generation
            // are unchanged when the source content is unchanged after restore.
            for table in [
                "source_projections",
                "source_occurrences",
                "source_entity_projections",
                "source_session_projections",
            ] {
                conn.execute(
                    &format!("UPDATE {table} SET revision_id=?2 WHERE source_id=?1"),
                    params![b.source_id.as_str(), o.revision_id.as_str()],
                )
                .map_err(sql)?;
            }
        }
        conn.execute("UPDATE source_heads SET visible_revision_id=?2,latest_receipt_id=?3,content_set_digest=?4,last_attempt_id=?3,update_state='current',observed_cycle_seq=?5 WHERE source_id=?1",params![b.source_id.as_str(),content_revision,o.revision_id.as_str(),digest_value,o.cycle_seq]).map_err(sql)?;
        conn.execute(
            "DELETE FROM source_scope_claims WHERE source_id=?1",
            [b.source_id.as_str()],
        )
        .map_err(sql)?;
        for selection in &o.selections {
            conn.execute(
                "INSERT INTO source_scope_claims VALUES(?1,?2,?3,?4,?5)",
                params![
                    b.source_id.as_str(),
                    selection.selection_id,
                    selection.selection_revision,
                    o.policy_epoch,
                    o.observed_at_ms
                ],
            )
            .map_err(sql)?;
        }
        if destructive {
            conn.execute(
                "UPDATE store_metadata SET destructive_epoch=destructive_epoch+1 WHERE singleton=1",
                [],
            )
            .map_err(sql)?;
        }
    } else {
        conn.execute(
            "UPDATE source_heads SET last_attempt_id=?2,update_state=?3 WHERE source_id=?1",
            params![
                b.source_id.as_str(),
                o.revision_id.as_str(),
                if matches!(
                    o.state,
                    ObservationState::RewritePending | ObservationState::DeletionPending
                ) {
                    "deferred"
                } else {
                    "partial"
                }
            ],
        )
        .map_err(sql)?;
    }
    Ok(Publication {
        receipt: RevisionRef {
            revision_id: o.revision_id.clone(),
            digest: o.revision_digest.clone(),
            observed_at_ms: o.observed_at_ms,
            cycle_seq: o.cycle_seq,
            worker_boot_id: o.worker_boot_id.clone(),
            catalog_incarnation: o.catalog_incarnation.clone(),
            policy_epoch: o.policy_epoch,
            started_control_seq: o.started_control_seq,
            committed_generation: published.then_some(committed_generation),
            published,
        },
        content_changed: changed,
        destructive,
        required_generation: committed_generation,
        destructive_epoch: epoch
            .checked_add(i64::from(destructive))
            .ok_or_else(invalid)?,
    })
}

/// After the caller's generation CAS, bind every receipt inserted by this outer
/// transaction to its final generation, including no-op observations beside a
/// changed source. Pass ALL publications from this transaction, before COMMIT.
/// Pure no-op transactions retain their old generation. Does not perform CAS.
pub fn finalize_publications_in_tx(
    conn: &Connection,
    publications: &mut [Publication],
) -> PortResult<()> {
    in_transaction(conn)?;
    let generation: i64 = conn
        .query_row(
            "SELECT active_generation FROM store_metadata WHERE singleton=1",
            [],
            |r| r.get(0),
        )
        .map_err(sql)?;
    if publications
        .iter()
        .any(|p| p.required_generation > generation)
    {
        return Err(invalid());
    }
    for publication in publications {
        if !publication.receipt.published {
            continue;
        }
        let updated=conn.execute("UPDATE source_revision_receipts SET committed_generation=?2 WHERE revision_id=?1 AND published=1 AND revision_digest=?3 AND committed_generation<=?2",params![publication.receipt.revision_id.as_str(),generation,publication.receipt.digest]).map_err(sql)?;
        if updated != 1 {
            return Err(corrupt());
        }
        publication.receipt.committed_generation = Some(generation);
    }
    Ok(())
}

fn validate_binding(conn: &Connection, b: &SourceBinding) -> PortResult<()> {
    let valid:bool=conn.query_row("SELECT EXISTS(SELECT 1 FROM source_bindings WHERE source_id=?1 AND source_path=?2 AND provider_id=?3 AND namespace_id IS ?4 AND root_identity=?5)",params![b.source_id.as_str(),b.source_path,b.provider.as_str(),b.namespace_id,b.root_identity],|r|r.get(0)).map_err(sql)?;
    if valid { Ok(()) } else { Err(corrupt()) }
}
pub(crate) fn retained_receipt_matches(
    conn: &Connection,
    revision: &RevisionRef,
    current_incarnation: &str,
    current_generation: i64,
) -> PortResult<bool> {
    if !revision.published || revision.catalog_incarnation == current_incarnation {
        return Ok(false);
    }
    let row: Option<(String, String, String, i64, String)> = conn.query_row(
        "SELECT retained_incarnation,original_incarnation,revision_digest,committed_generation,operation_id FROM retained_source_receipts WHERE revision_id=?1",
        [revision.revision_id.as_str()], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?))
    ).optional().map_err(sql)?;
    let Some((retained, original, digest, generation, operation)) = row else {
        return Ok(false);
    };
    for value in [&retained, &original, &operation] {
        control::ControlId::parse(value).map_err(|_| corrupt())?;
    }
    if generation < 0 {
        return Err(corrupt());
    }
    Ok(retained == current_incarnation
        && original == revision.catalog_incarnation
        && digest == revision.digest
        && revision.committed_generation == Some(generation)
        && generation <= current_generation)
}

fn stored_fingerprints(conn: &Connection, source: &str) -> PortResult<BTreeMap<String, String>> {
    let mut statement=conn.prepare("SELECT 'm:'||message_id,payload_digest FROM source_projections WHERE source_id=?1 UNION ALL SELECT 'o:'||placement_id,payload_digest FROM source_occurrences WHERE source_id=?1 UNION ALL SELECT 'e:'||kind||':'||entity_key,payload_digest FROM source_entity_projections WHERE source_id=?1").map_err(sql)?;
    statement
        .query_map([source], |r| Ok((r.get(0)?, r.get(1)?)))
        .map_err(sql)?
        .collect::<Result<_, _>>()
        .map_err(sql)
}

fn write_prepared(
    conn: &Connection,
    source: &str,
    revision: &str,
    data: &Prepared,
) -> PortResult<()> {
    conn.execute_batch("CREATE TEMP TABLE IF NOT EXISTS incoming_projection_keys(kind TEXT,key TEXT,PRIMARY KEY(kind,key)) WITHOUT ROWID; DELETE FROM incoming_projection_keys;").map_err(sql)?;
    for (key, message) in &data.messages {
        let payload = encode(message)?;
        let pd = digest(&[&payload]);
        let text = bounded_index_text(&message.text);
        let index = digest(&[text.as_bytes()]);
        let id = format!(
            "prj_v1_{}",
            digest(&[source.as_bytes(), key.as_bytes(), pd.as_bytes()])
        );
        conn.execute(
            "INSERT INTO incoming_projection_keys VALUES('message',?1)",
            [key],
        )
        .map_err(sql)?;
        conn.execute("INSERT INTO source_projections(projection_id,source_id,revision_id,message_id,payload,payload_digest,index_text,index_digest,fts_text) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9) ON CONFLICT(source_id,message_id) DO UPDATE SET projection_id=excluded.projection_id,revision_id=excluded.revision_id,payload=excluded.payload,payload_digest=excluded.payload_digest,index_text=excluded.index_text,index_digest=excluded.index_digest,fts_text=excluded.fts_text WHERE source_projections.payload_digest!=excluded.payload_digest",params![id,source,revision,key,payload,pd,text,index,fts_tokens_cjk(&text)]).map_err(sql)?;
    }
    for (key, occurrence) in &data.occurrences {
        let p = &occurrence.placement;
        let payload = encode(occurrence)?;
        let pd = digest(&[&payload]);
        let instant = occurrence
            .timestamp
            .as_deref()
            .and_then(parse_search_instant);
        let role = match occurrence.role {
            Role::User => "user",
            Role::Assistant => "assistant",
            Role::System => "system",
            Role::Developer => "developer",
            Role::Tool => "tool",
        };
        let start = p
            .span
            .as_ref()
            .map(|s| i64::try_from(s.start))
            .transpose()
            .map_err(|_| invalid())?;
        let end = p
            .span
            .as_ref()
            .map(|s| i64::try_from(s.end))
            .transpose()
            .map_err(|_| invalid())?;
        conn.execute(
            "INSERT INTO incoming_projection_keys VALUES('occurrence',?1)",
            [key],
        )
        .map_err(sql)?;
        conn.execute("INSERT INTO source_occurrences(source_id,revision_id,message_id,session_id,document_id,placement_id,provider_id,project_id,instant_unix_seconds,instant_nanosecond,role,is_sidechain,byte_start,byte_end,source_ordinal,precision,payload,payload_digest) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18) ON CONFLICT(source_id,placement_id) DO UPDATE SET revision_id=excluded.revision_id,project_id=excluded.project_id,instant_unix_seconds=excluded.instant_unix_seconds,instant_nanosecond=excluded.instant_nanosecond,role=excluded.role,is_sidechain=excluded.is_sidechain,byte_start=excluded.byte_start,byte_end=excluded.byte_end,precision=excluded.precision,payload=excluded.payload,payload_digest=excluded.payload_digest WHERE source_occurrences.payload_digest!=excluded.payload_digest",params![source,revision,p.message_id.as_str(),p.session_id.as_str(),p.source_document_id.as_str(),key,occurrence.provider_id,occurrence.project_id,instant.map(|v|v.unix_seconds),instant.map(|v|v.nanosecond),role,p.is_sidechain,start,end,p.source_ordinal,if p.span.is_some(){"byte_span"}else{"message"},payload,pd]).map_err(sql)?;
    }
    for ((kind, key), (id, parent, entity)) in &data.entities {
        let payload = encode(entity)?;
        let pd = digest(&[&payload]);
        let projection = format!(
            "prj_v1_{}",
            digest(&[
                source.as_bytes(),
                kind.as_bytes(),
                key.as_bytes(),
                pd.as_bytes()
            ])
        );
        conn.execute(
            "INSERT INTO incoming_projection_keys VALUES(?1,?2)",
            params![kind, key],
        )
        .map_err(sql)?;
        conn.execute("INSERT INTO source_entity_projections(projection_id,source_id,revision_id,kind,entity_key,entity_id,parent_id,payload,payload_digest) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9) ON CONFLICT(source_id,kind,entity_key) DO UPDATE SET projection_id=excluded.projection_id,revision_id=excluded.revision_id,parent_id=excluded.parent_id,payload=excluded.payload,payload_digest=excluded.payload_digest WHERE source_entity_projections.payload_digest!=excluded.payload_digest",params![projection,source,revision,kind,key,id,parent,payload,pd]).map_err(sql)?;
        if let EntityData::Session(session) = entity {
            let text = bounded_index_text(
                &[
                    session.title.as_deref().unwrap_or(""),
                    session.repo_slug.as_deref().unwrap_or(""),
                    &session.provider_id,
                    session.first_user_text.as_deref().unwrap_or(""),
                ]
                .join("\n"),
            );
            let sd = digest(&[text.as_bytes()]);
            conn.execute("INSERT INTO source_session_projections(source_id,revision_id,session_id,title,search_text,search_digest,fts_text,repo_slug) VALUES(?1,?2,?3,?4,?5,?6,?7,?8) ON CONFLICT(source_id,session_id) DO UPDATE SET revision_id=excluded.revision_id,title=excluded.title,search_text=excluded.search_text,search_digest=excluded.search_digest,fts_text=excluded.fts_text,repo_slug=excluded.repo_slug WHERE source_session_projections.search_digest!=excluded.search_digest",params![source,revision,id,session.title,text,sd,fts_tokens_cjk(&text),session.repo_slug]).map_err(sql)?;
        }
    }
    conn.execute("DELETE FROM source_projections WHERE source_id=?1 AND message_id NOT IN(SELECT key FROM incoming_projection_keys WHERE kind='message')",[source]).map_err(sql)?;
    conn.execute("DELETE FROM source_occurrences WHERE source_id=?1 AND placement_id NOT IN(SELECT key FROM incoming_projection_keys WHERE kind='occurrence')",[source]).map_err(sql)?;
    conn.execute("DELETE FROM source_entity_projections WHERE source_id=?1 AND NOT EXISTS(SELECT 1 FROM incoming_projection_keys i WHERE i.kind=source_entity_projections.kind AND i.key=entity_key)",[source]).map_err(sql)?;
    conn.execute("DELETE FROM source_session_projections WHERE source_id=?1 AND session_id NOT IN(SELECT key FROM incoming_projection_keys WHERE kind='session')",[source]).map_err(sql)?;
    conn.execute("INSERT OR REPLACE INTO projection_fts_stats SELECT p.projection_rowid,CAST(json_extract(managed_fts_stats(projection_fts),'$[0]') AS INTEGER),p.index_digest FROM projection_fts JOIN source_projections p ON p.projection_rowid=projection_fts.rowid WHERE p.source_id=?1",[source]).map_err(sql)?;
    conn.execute("INSERT OR REPLACE INTO session_fts_stats SELECT p.session_projection_rowid,CAST(json_extract(managed_fts_stats(session_metadata_fts),'$[0]') AS INTEGER),p.search_digest FROM session_metadata_fts JOIN source_session_projections p ON p.session_projection_rowid=session_metadata_fts.rowid WHERE p.source_id=?1",[source]).map_err(sql)?;
    Ok(())
}

/// Register the real FTS5 row auxiliary on each dedicated catalog connection.
/// It returns [token_count, phrase_0_tf, ...], never global corpus statistics.
pub fn register_fts(conn: &Connection) -> PortResult<()> {
    let mut api: *mut ffi::fts5_api = std::ptr::null_mut();
    let mut statement = std::ptr::null_mut();
    // SAFETY: conn owns the live SQLite handle; statement and api are writable
    // stack slots. SQLite consumes the pointer binding synchronously before
    // finalize; no statement/binding pointer escapes this call.
    unsafe {
        let db = conn.handle();
        if ffi::sqlite3_prepare_v2(
            db,
            c"SELECT fts5(?1)".as_ptr(),
            -1,
            &mut statement,
            std::ptr::null_mut(),
        ) != ffi::SQLITE_OK
        {
            return Err(corrupt());
        }
        let bound = ffi::sqlite3_bind_pointer(
            statement,
            1,
            (&mut api as *mut *mut ffi::fts5_api).cast(),
            c"fts5_api_ptr".as_ptr(),
            None,
        );
        let stepped = if bound == ffi::SQLITE_OK {
            ffi::sqlite3_step(statement)
        } else {
            bound
        };
        ffi::sqlite3_finalize(statement);
        if stepped != ffi::SQLITE_ROW || api.is_null() {
            return Err(corrupt());
        }
        let create = (*api).xCreateFunction.ok_or_else(corrupt)?;
        if create(
            api,
            c"managed_fts_stats".as_ptr(),
            std::ptr::null_mut(),
            Some(fts_stats),
            None,
        ) != ffi::SQLITE_OK
        {
            return Err(corrupt());
        }
    }
    Ok(())
}

unsafe extern "C" fn fts_stats(
    api: *const ffi::Fts5ExtensionApi,
    fts: *mut ffi::Fts5Context,
    context: *mut ffi::sqlite3_context,
    _argc: i32,
    _args: *mut *mut ffi::sqlite3_value,
) {
    // SAFETY: SQLite supplies valid callback pointers for this invocation only.
    // Catch unwinding before crossing the FFI boundary. Result text is copied
    // with SQLITE_TRANSIENT before the local allocation is released.
    let result = std::panic::catch_unwind(|| unsafe {
        let api = api.as_ref().ok_or(ffi::SQLITE_ERROR)?;
        let mut count = 0;
        let rc = api.xColumnSize.ok_or(ffi::SQLITE_ERROR)?(fts, 0, &mut count);
        if rc != ffi::SQLITE_OK || count < 0 {
            return Err(ffi::SQLITE_ERROR);
        }
        let phrases = api.xPhraseCount.ok_or(ffi::SQLITE_ERROR)?(fts);
        let mut stats = vec![
            0_u32;
            usize::try_from(phrases)
                .map_err(|_| ffi::SQLITE_ERROR)?
                .checked_add(1)
                .ok_or(ffi::SQLITE_TOOBIG)?
        ];
        stats[0] = count as u32;
        if phrases > 0 {
            let mut instances = 0;
            let rc = api.xInstCount.ok_or(ffi::SQLITE_ERROR)?(fts, &mut instances);
            if rc != ffi::SQLITE_OK || instances < 0 {
                return Err(ffi::SQLITE_ERROR);
            }
            for index in 0..instances {
                let (mut phrase, mut column, mut offset) = (0, 0, 0);
                let rc = api.xInst.ok_or(ffi::SQLITE_ERROR)?(
                    fts,
                    index,
                    &mut phrase,
                    &mut column,
                    &mut offset,
                );
                if rc != ffi::SQLITE_OK || phrase < 0 || phrase >= phrases || column != 0 {
                    return Err(ffi::SQLITE_ERROR);
                }
                stats[phrase as usize + 1] = stats[phrase as usize + 1]
                    .checked_add(1)
                    .ok_or(ffi::SQLITE_TOOBIG)?;
            }
        }
        serde_json::to_string(&stats).map_err(|_| ffi::SQLITE_ERROR)
    });
    unsafe {
        match result {
            Ok(Ok(text)) => match i32::try_from(text.len()) {
                Ok(len) => ffi::sqlite3_result_text(
                    context,
                    text.as_ptr().cast(),
                    len,
                    ffi::SQLITE_TRANSIENT(),
                ),
                Err(_) => ffi::sqlite3_result_error_code(context, ffi::SQLITE_TOOBIG),
            },
            Ok(Err(code)) => ffi::sqlite3_result_error_code(context, code),
            Err(_) => ffi::sqlite3_result_error_code(context, ffi::SQLITE_ERROR),
        }
    }
}

/// Validated catalog discovery row; never a control scheduling summary.
struct DiscoveryReceipt {
    cycle_seq: i64,
    selection_revision: i64,
    worker_boot_id: String,
    policy_epoch: i64,
    started_control_seq: i64,
    catalog_incarnation: String,
    root_identity: String,
    source_set_digest: String,
    complete: bool,
    committed_generation: i64,
}

/// Snapshot capability for authorized projection reads and catalog-only latest
/// verification. It must not outlive the caller's catalog handle guard.
/// Policy emission needs a separate current-control recheck.
pub struct ManagedRead<'a> {
    transaction: Transaction<'a>,
    snapshot: ReadSnapshot,
    deadline: Instant,
    /// Captured by the authorized constructor. An explicit test allow-list
    /// alone cannot prove that a barrier's selection revision/root is current.
    policy: Option<control::ReadPolicy>,
}
/// Content-free counts from one authorized catalog snapshot. Coverage records
/// verified selected discovery, independently of worker lifecycle or a latest
/// request. Observation time is display-only and never grants liveness.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SnapshotFreshness {
    pub coverage: control::Coverage,
    pub selected_scopes: u64,
    pub complete_scopes: u64,
    pub sources: u64,
    pub verified_sources: u64,
    pub pending_sources: u64,
    pub failed_sources: u64,
    pub last_verified_observation_at_ms: Option<i64>,
}
impl Default for SnapshotFreshness {
    fn default() -> Self {
        Self {
            coverage: control::Coverage::Empty,
            selected_scopes: 0,
            complete_scopes: 0,
            sources: 0,
            verified_sources: 0,
            pending_sources: 0,
            failed_sources: 0,
            last_verified_observation_at_ms: None,
        }
    }
}

impl<'a> ManagedRead<'a> {
    /// Cache admission requires the actual policy captured by begin_authorized;
    /// a caller-provided test allow-list is not equivalent authorization.
    pub(crate) fn authorized_policy(&self) -> Option<&control::ReadPolicy> {
        self.policy.as_ref()
    }

    /// Verify the cached source projection itself, never a canonical ID's
    /// current default representative. All checks use this authorized snapshot.
    pub(crate) fn verify_cache_entry(
        &self,
        entry: &ProjectionListEntry,
        query: &ProjectionQuery,
    ) -> PortResult<bool> {
        if self.authorized_policy().is_none() {
            return Ok(false);
        }
        match entry {
            ProjectionListEntry::Message(expected) => {
                self.qualify(query)?;
                let rowid:Option<i64>=self.transaction.query_row("SELECT p.projection_rowid FROM source_projections p JOIN qualified_projections q USING(projection_rowid) WHERE p.projection_id=?1 AND p.source_id=?2",params![expected.proof.projection_id.as_str(),expected.proof.source_id.as_str()],|r|r.get(0)).optional().map_err(sql)?;
                let Some(rowid) = rowid else { return Ok(false) };
                let mut actual = self.message_row(rowid)?;
                let Some(occurrence) = &expected.occurrence else {
                    return Ok(false);
                };
                let stored:Option<(Vec<u8>,String,String)>=self.transaction.query_row("SELECT o.payload,o.revision_id,o.payload_digest FROM source_occurrences o JOIN qualified_occurrences q USING(occurrence_rowid) WHERE o.source_id=?1 AND o.placement_id=?2",params![expected.proof.source_id.as_str(),occurrence.data.placement.id.as_str()],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional().map_err(sql)?;
                let Some((payload, revision, expected_digest)) = stored else {
                    return Ok(false);
                };
                if digest(&[&payload]) != expected_digest {
                    return Err(corrupt());
                }
                actual.occurrence = Some(OccurrenceProjection {
                    data: decode(&payload)?,
                    source_id: expected.proof.source_id.clone(),
                    revision: self.revision(&revision)?,
                });
                Ok(actual == **expected)
            }
            ProjectionListEntry::Entity(expected) => {
                let (kind, id) = match &expected.data {
                    EntityData::Session(s) => (EntityKind::Session, &s.session.id),
                    EntityData::Document(d) => (EntityKind::Document, &d.id),
                    _ => return Ok(false),
                };
                Ok(self
                    .entities(kind, std::slice::from_ref(id), query)?
                    .contains(expected))
            }
        }
    }

    /// Verify every retained fact and supporting proof before it enters cache.
    /// This checks catalog provenance, not whether arbitrary supplied prose is
    /// a valid Application rendering; only App-produced candidates are inputs.
    pub(crate) fn verify_cache_evidence(
        &self,
        evidence: &[agent_session_grep_application::managed::ManagedEvidence],
        query: &ProjectionQuery,
    ) -> PortResult<bool> {
        if self.authorized_policy().is_none() || evidence.len() > 2048 {
            return Ok(false);
        }
        self.qualify(query)?;
        for item in evidence {
            self.check_deadline()?;
            for proof in std::iter::once(&item.proof).chain(&item.related) {
                let source = proof.source_id.as_str();
                let projection = proof.projection_id.as_str();
                let message:Option<i64>=self.transaction.query_row("SELECT p.projection_rowid FROM source_projections p JOIN qualified_projections q USING(projection_rowid) WHERE p.source_id=?1 AND p.projection_id=?2",params![source,projection],|r|r.get(0)).optional().map_err(sql)?;
                if let Some(rowid) = message {
                    let actual = self.message_row(rowid)?;
                    if actual.proof != *proof {
                        return Ok(false);
                    }
                    if proof == &item.proof {
                        if actual.message.id.as_str() != item.entity_id.as_str() {
                            return Ok(false);
                        }
                        if let Some(occurrence) = &item.occurrence {
                            let mut exact = actual;
                            exact.occurrence = Some(occurrence.clone());
                            if !self.verify_cache_entry(
                                &ProjectionListEntry::Message(Box::new(exact)),
                                query,
                            )? {
                                return Ok(false);
                            }
                        }
                    }
                } else {
                    let row:Option<(Vec<u8>,String,String,String)>=self.transaction.query_row("SELECT e.payload,e.payload_digest,e.revision_id,e.entity_id FROM source_entity_projections e JOIN allowed_sources a USING(source_id) JOIN source_revision_receipts r ON r.revision_id=e.revision_id AND r.source_id=e.source_id JOIN source_heads h ON h.source_id=e.source_id WHERE e.source_id=?1 AND e.projection_id=?2 AND r.published=1 AND h.visible_revision_id IS NOT NULL AND h.update_state!='revoked'",params![source,projection],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).optional().map_err(sql)?;
                    let Some((payload, payload_digest, revision, id)) = row else {
                        return Ok(false);
                    };
                    if digest(&[&payload]) != payload_digest {
                        return Err(corrupt());
                    }
                    if self.revision(&revision)? != proof.revision
                        || !self.entity_qualifies(&decode(&payload)?, source, &id, query)?
                    {
                        return Ok(false);
                    }
                    if proof == &item.proof
                        && (item.occurrence.is_some() || id != item.entity_id.as_str())
                    {
                        return Ok(false);
                    }
                }
            }
        }
        Ok(true)
    }
    /// Enumerate and authorize only persisted source bindings inside the same
    /// pinned transaction as all evidence reads. Offline sources remain usable;
    /// no filesystem probing, source content access or legacy membership read.
    pub fn begin_authorized(
        conn: &'a Connection,
        policy: &agent_session_grep_ports::control::ReadPolicy,
        incarnation: &str,
        deadline: Instant,
    ) -> PortResult<Self> {
        use agent_session_grep_ports::control::{CanonicalLocator, ControlId};
        policy.maintenance.validate().map_err(|_| corrupt())?;
        if policy.emission_blocked() {
            return Err(PortError::WriterBusy(
                "managed policy admission is blocked".into(),
            ));
        }
        let mut read = Self::begin(
            conn,
            &ReadScope {
                catalog_incarnation: incarnation.into(),
                policy_epoch: policy.policy_epoch.get(),
                allowed: Vec::new(),
            },
            deadline,
        )?;
        let installation: String = read
            .transaction
            .query_row(
                "SELECT installation_id FROM catalog_meta WHERE singleton=1",
                [],
                |r| r.get(0),
            )
            .map_err(sql)?;
        if installation != policy.installation_id.as_str() {
            return Err(corrupt());
        }
        {
            let mut statement=read.transaction.prepare("SELECT source_id,source_path,provider_id,namespace_id,root_identity FROM source_bindings ORDER BY source_id").map_err(sql)?;
            let mut rows = statement.query([]).map_err(sql)?;
            while let Some(row) = rows.next().map_err(sql)? {
                read.check_deadline()?;
                let source: String = row.get(0).map_err(sql)?;
                SourceId::parse(&source).map_err(|_| corrupt())?;
                let source_id = ControlId::parse(&source).map_err(|_| corrupt())?;
                let locator = CanonicalLocator::parse(&row.get::<_, String>(1).map_err(sql)?)
                    .map_err(|_| corrupt())?;
                let provider_wire: String = row.get(2).map_err(sql)?;
                let provider = agent_session_grep_ports::SearchProvider::parse(&provider_wire)
                    .filter(|p| p.as_str() == provider_wire)
                    .ok_or_else(corrupt)?;
                let namespace: Option<String> = row.get(3).map_err(sql)?;
                if let Some(namespace) = namespace {
                    ControlId::parse(&namespace).map_err(|_| corrupt())?;
                }
                // The binding root is historical evidence, not authority over
                // every overlapping selection. A selection revision pins its own
                // root identity, and the scope claim below proves that revision
                // validated this source.
                ControlId::parse(&row.get::<_, String>(4).map_err(sql)?).map_err(|_| corrupt())?;
                if !policy.allows_source(provider, &locator, &source_id) {
                    continue;
                }
                let mut verified = false;
                for selection in &policy.selections {
                    if !selection.enabled || !selection.region.matches(provider, &locator) {
                        continue;
                    }
                    verified=read.transaction.query_row("SELECT EXISTS(SELECT 1 FROM source_scope_claims WHERE source_id=?1 AND selection_id=?2 AND selection_revision=?3)",params![source,selection.id.as_str(),selection.revision.get()],|r|r.get(0)).map_err(sql)?;
                    if verified {
                        break;
                    }
                }
                if !verified {
                    // A first partial observation or a new selection revision
                    // has no current verification claim yet. Keep its receipt
                    // for progress, but do not admit its evidence or fail other
                    // permitted sources. Malformed bindings were rejected above.
                    continue;
                }
                if !crate::managed_source_context::source_read_eligible(&read.transaction, &source)?
                {
                    continue;
                }
                read.transaction
                    .execute("INSERT INTO allowed_sources VALUES(?1)", [source])
                    .map_err(sql)?;
            }
        }
        read.policy = Some(policy.clone());
        Ok(read)
    }
    pub fn begin(conn: &'a Connection, scope: &ReadScope, deadline: Instant) -> PortResult<Self> {
        if !conn.is_autocommit() || deadline <= Instant::now() {
            return Err(invalid());
        }
        // Dedicated connection: SQLite busy retries must not restart the request
        // budget. The caller can retry using the same remaining deadline.
        conn.busy_handler(Some(|_| false)).map_err(sql)?;
        conn.progress_handler(1000, Some(move || Instant::now() >= deadline))
            .map_err(sql)?;
        struct ResetProgress<'a>(&'a Connection, bool);
        impl Drop for ResetProgress<'_> {
            fn drop(&mut self) {
                if self.1 {
                    let _ = self.0.progress_handler(0, None::<fn() -> bool>);
                }
            }
        }
        let mut reset = ResetProgress(conn, true);
        register_fts(conn)?;
        let transaction = conn.unchecked_transaction().map_err(sql)?;
        // First main-database read pins the WAL snapshot before any binding or
        // permission relation is materialized. The caller supplies current control.
        let (incarnation,generation,epoch):(String,i64,i64)=transaction.query_row("SELECT catalog_incarnation,active_generation,destructive_epoch FROM catalog_meta CROSS JOIN store_metadata WHERE catalog_meta.singleton=1 AND store_metadata.singleton=1 AND managed_mode=1 AND projection_contract_version=1",[],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).map_err(sql)?;
        if incarnation != scope.catalog_incarnation
            || generation < 0
            || epoch < 0
            || scope.policy_epoch < 0
        {
            return Err(corrupt());
        }
        transaction.execute_batch("CREATE TEMP TABLE IF NOT EXISTS allowed_sources(source_id TEXT PRIMARY KEY) WITHOUT ROWID; DELETE FROM allowed_sources; CREATE TEMP TABLE IF NOT EXISTS qualified_projections(projection_rowid INTEGER PRIMARY KEY) WITHOUT ROWID; CREATE TEMP TABLE IF NOT EXISTS qualified_occurrences(occurrence_rowid INTEGER PRIMARY KEY) WITHOUT ROWID;").map_err(sql)?;
        for binding in &scope.allowed {
            if Instant::now() >= deadline {
                return Err(timeout());
            }
            validate_binding(&transaction, binding)?;
            if !crate::managed_source_context::source_read_eligible(
                &transaction,
                binding.source_id.as_str(),
            )? {
                continue;
            }
            transaction
                .execute(
                    "INSERT INTO allowed_sources VALUES(?1)",
                    [binding.source_id.as_str()],
                )
                .map_err(sql)?;
        }
        reset.1 = false;
        Ok(Self {
            transaction,
            snapshot: ReadSnapshot {
                catalog_incarnation: incarnation,
                generation,
                destructive_epoch: epoch,
                policy_epoch: scope.policy_epoch,
            },
            deadline,
            policy: None,
        })
    }
    fn check_deadline(&self) -> PortResult<()> {
        if Instant::now() >= self.deadline {
            Err(timeout())
        } else {
            Ok(())
        }
    }

    /// Prove this barrier against the SAME pinned catalog snapshot as output.
    /// Only begin_authorized captures current selection/root authority. The
    /// explicit test constructor cannot prove latest and returns false here.
    /// Scheduling state (including AwaitingCatalog or an aborted cycle) and
    /// wall-clock observation times are deliberately not completion evidence.
    /// The caller still rechecks current policy under its emission guard.
    /// Each discovery set is bounded at 65,536 entries; exceeding it is busy,
    /// never an incomplete set reported as satisfied.
    pub fn latest_satisfied(&self, barrier: &control::LatestBarrier) -> PortResult<bool> {
        self.check_deadline()?;
        if barrier.selections.is_empty()
            || barrier.selections.len() > 4096
            || barrier.admitted_at_ms < 0
            || barrier.requested_wait_ms > control::MAX_LATEST_WAIT_MS
        {
            return Err(invalid());
        }
        let mut unique = BTreeSet::new();
        if barrier
            .selections
            .iter()
            .any(|s| !unique.insert(&s.selection_id))
        {
            return Err(invalid());
        }
        let Some(policy) = self.authorized_policy() else {
            return Ok(false);
        };
        if barrier.policy_epoch.get() != self.snapshot.policy_epoch
            || barrier.admission_control_seq > policy.control_seq
        {
            return Ok(false);
        }
        for selection in &barrier.selections {
            self.check_deadline()?;
            let mut current = policy
                .selections
                .iter()
                .filter(|s| s.id == selection.selection_id);
            let Some(current_selection) = current.next() else {
                return Ok(false);
            };
            if current.next().is_some() {
                return Err(corrupt());
            }
            if !current_selection.enabled
                || current_selection.revision != selection.revision
                || current_selection.root_identity.as_ref() != Some(&selection.root_identity)
                || !self.selection_discovery_verified(current_selection, Some(barrier))?
            {
                return Ok(false);
            }
        }
        self.check_deadline()?;
        Ok(true)
    }

    /// Ordinary as-of coverage uses the same catalog discovery/source proof as
    /// latest, without inventing a post-request observation or enqueueing work.
    /// Unknown future matching sources keep incomplete selections partial.
    pub fn scope_freshness(
        &self,
        providers: &[agent_session_grep_ports::SearchProvider],
    ) -> PortResult<SnapshotFreshness> {
        let Some(policy) = self.authorized_policy() else {
            return Err(invalid());
        };
        let mut summary = self.source_freshness(providers, None)?;
        for selection in policy.selections.iter().filter(|s| {
            s.enabled && (providers.is_empty() || providers.contains(&s.region.provider))
        }) {
            self.check_deadline()?;
            summary.selected_scopes += 1;
            if self.selection_discovery_verified(selection, None)? {
                summary.complete_scopes += 1;
            }
        }
        summary.coverage = if summary.selected_scopes == summary.complete_scopes {
            if summary.sources == 0 {
                control::Coverage::Empty
            } else {
                control::Coverage::Complete
            }
        } else {
            control::Coverage::Partial
        };
        Ok(summary)
    }

    /// Count only returned, currently permitted proof contributors for direct
    /// evidence. A failed unrelated or forbidden source cannot appear here.
    pub fn contributing_freshness(&self, sources: &[SourceId]) -> PortResult<SnapshotFreshness> {
        self.source_freshness(&[], Some(sources))
    }

    fn source_freshness(
        &self,
        providers: &[agent_session_grep_ports::SearchProvider],
        contributors: Option<&[SourceId]>,
    ) -> PortResult<SnapshotFreshness> {
        self.check_deadline()?;
        let Some(policy) = self.authorized_policy() else {
            return Err(invalid());
        };
        if contributors.is_some_and(|ids| ids.len() > 4096) {
            return Err(invalid());
        }
        let mut summary = SnapshotFreshness::default();
        let mut statement = self.transaction.prepare("SELECT b.source_id,b.provider_id,b.source_path,h.latest_receipt_id,h.last_attempt_id,h.update_state FROM source_bindings b LEFT JOIN source_heads h USING(source_id) ORDER BY b.source_id").map_err(sql)?;
        let mut rows = statement.query([]).map_err(sql)?;
        while let Some(row) = rows.next().map_err(sql)? {
            self.check_deadline()?;
            let source: String = row.get(0).map_err(sql)?;
            let source_id = SourceId::parse(&source).map_err(|_| corrupt())?;
            let provider_wire: String = row.get(1).map_err(sql)?;
            let provider = agent_session_grep_ports::SearchProvider::parse(&provider_wire)
                .filter(|p| p.as_str() == provider_wire)
                .ok_or_else(corrupt)?;
            let locator = control::CanonicalLocator::parse(&row.get::<_, String>(2).map_err(sql)?)
                .map_err(|_| corrupt())?;
            if (!providers.is_empty() && !providers.contains(&provider))
                || contributors.is_some_and(|ids| !ids.contains(&source_id))
                || !policy.allows_source(
                    provider,
                    &locator,
                    &control::ControlId::parse(&source).map_err(|_| corrupt())?,
                )
            {
                continue;
            }
            summary.sources += 1;
            let latest: Option<String> = row.get(3).map_err(sql)?;
            let attempt: Option<String> = row.get(4).map_err(sql)?;
            let state: Option<String> = row.get(5).map_err(sql)?;
            if state.as_deref().is_some_and(|s| {
                !matches!(
                    s,
                    "unknown"
                        | "current"
                        | "partial"
                        | "failed"
                        | "deferred"
                        | "paused"
                        | "revoked"
                )
            }) {
                return Err(corrupt());
            }
            let latest = latest
                .map(|id| {
                    crate::managed_receipt::read_checked(&self.transaction, &id, Some(&source))
                })
                .transpose()?;
            let attempt = attempt
                .map(|id| {
                    crate::managed_receipt::read_checked(&self.transaction, &id, Some(&source))
                })
                .transpose()?;
            if let Some(receipt) = &latest {
                if receipt.observed_at_ms < 0
                    || !receipt.published
                    || receipt
                        .committed_generation
                        .is_none_or(|g| g < 0 || g > self.snapshot.generation)
                {
                    return Err(corrupt());
                }
                if receipt.catalog_incarnation != self.snapshot.catalog_incarnation {
                    if !self.retained_revision_allowed(receipt)? {
                        return Err(corrupt());
                    }
                    summary.pending_sources += 1;
                    continue;
                }
                if !crate::managed_source_context::receipt_context_current(
                    &self.transaction,
                    receipt.revision_id.as_str(),
                    Some(policy),
                    self.deadline,
                )? {
                    summary.pending_sources += 1;
                    continue;
                }
                summary.verified_sources += 1;
                summary.last_verified_observation_at_ms = Some(
                    summary
                        .last_verified_observation_at_ms
                        .map_or(receipt.observed_at_ms, |at| at.min(receipt.observed_at_ms)),
                );
            }
            if latest.is_none() || attempt.as_ref().is_some_and(|r| !r.published) {
                summary.pending_sources += 1;
            }
            if state.as_deref() == Some("failed") {
                summary.failed_sources += 1;
            }
        }
        summary.coverage = if summary.sources == 0 {
            control::Coverage::Empty
        } else if summary.pending_sources == 0 && summary.failed_sources == 0 {
            control::Coverage::Complete
        } else {
            control::Coverage::Partial
        };
        Ok(summary)
    }

    fn selection_discovery_verified(
        &self,
        selection: &control::Selection,
        barrier: Option<&control::LatestBarrier>,
    ) -> PortResult<bool> {
        let Some(policy) = self.authorized_policy() else {
            return Ok(false);
        };
        let Some(root) = selection.root_identity.as_ref() else {
            return Ok(false);
        };
        let Some(receipt) = self.discovery_receipt(selection.id.as_str())? else {
            return Ok(false);
        };
        let sources = self.discovery_sources(receipt.cycle_seq, selection.id.as_str())?;
        if crate::managed_discovery::source_set_digest(&sources).map_err(|_| corrupt())?
            != receipt.source_set_digest
        {
            return Err(corrupt());
        }
        if !receipt.complete
            || receipt.selection_revision != selection.revision.get()
            || receipt.root_identity != root.as_str()
            || receipt.policy_epoch != self.snapshot.policy_epoch
            || receipt.catalog_incarnation != self.snapshot.catalog_incarnation
            || barrier.is_some_and(|b| {
                receipt.cycle_seq < b.required_cycle_seq.get()
                    || receipt.started_control_seq <= b.admission_control_seq.get()
            })
        {
            return Ok(false);
        }
        for source in &sources {
            self.check_deadline()?;
            if !self.discovery_source_satisfied(source, &receipt, selection)? {
                return Ok(false);
            }
        }
        self.discovery_heads_covered(&sources, &receipt, selection, policy)
    }

    fn discovery_receipt(&self, selection: &str) -> PortResult<Option<DiscoveryReceipt>> {
        let mut statement = self.transaction.prepare("SELECT cycle_seq,selection_revision,worker_boot_id,policy_epoch,started_control_seq,catalog_incarnation,root_identity,source_set_digest,complete,committed_generation FROM discovery_receipts WHERE selection_id=?1 ORDER BY cycle_seq DESC LIMIT 1").map_err(sql)?;
        let mut rows = statement.query([selection]).map_err(sql)?;
        let Some(row) = rows.next().map_err(sql)? else {
            return Ok(None);
        };
        let complete: i64 = row.get(8).map_err(sql)?;
        let receipt = DiscoveryReceipt {
            cycle_seq: row.get(0).map_err(sql)?,
            selection_revision: row.get(1).map_err(sql)?,
            worker_boot_id: row.get(2).map_err(sql)?,
            policy_epoch: row.get(3).map_err(sql)?,
            started_control_seq: row.get(4).map_err(sql)?,
            catalog_incarnation: row.get(5).map_err(sql)?,
            root_identity: row.get(6).map_err(sql)?,
            source_set_digest: row.get(7).map_err(sql)?,
            complete: complete == 1,
            committed_generation: row.get(9).map_err(sql)?,
        };
        if receipt.cycle_seq <= 0
            || receipt.selection_revision < 0
            || receipt.policy_epoch < 0
            || receipt.started_control_seq < 0
            || !matches!(complete, 0 | 1)
            || receipt.committed_generation < 0
            || receipt.committed_generation > self.snapshot.generation
            || receipt.source_set_digest.len() != 64
            || !receipt
                .source_set_digest
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(corrupt());
        }
        for value in [
            &receipt.worker_boot_id,
            &receipt.catalog_incarnation,
            &receipt.root_identity,
        ] {
            control::ControlId::parse(value).map_err(|_| corrupt())?;
        }
        Ok(Some(receipt))
    }

    fn discovery_sources(&self, cycle: i64, selection: &str) -> PortResult<Vec<DiscoverySource>> {
        let mut statement = self.transaction.prepare("SELECT source_id,revision_id FROM discovery_sources WHERE cycle_seq=?1 AND selection_id=?2 ORDER BY source_id").map_err(sql)?;
        let mut rows = statement.query(params![cycle, selection]).map_err(sql)?;
        let mut sources = Vec::new();
        while let Some(row) = rows.next().map_err(sql)? {
            self.check_deadline()?;
            if sources.len() == 65_536 {
                return Err(PortError::WriterBusy(
                    "managed discovery proof exceeds bounded read capacity".into(),
                ));
            }
            sources.push(DiscoverySource {
                source_id: SourceId::parse(&row.get::<_, String>(0).map_err(sql)?)
                    .map_err(|_| corrupt())?,
                revision_id: RevisionId::parse(&row.get::<_, String>(1).map_err(sql)?)
                    .map_err(|_| corrupt())?,
            });
        }
        Ok(sources)
    }

    fn discovery_source_satisfied(
        &self,
        source: &DiscoverySource,
        discovery: &DiscoveryReceipt,
        selection: &control::Selection,
    ) -> PortResult<bool> {
        let mut statement = self.transaction.prepare("SELECT r.source_id,r.completeness,r.content_revision_id,r.content_set_digest,r.committed_at_ms,r.parser_version,r.revision_seq,r.reason,b.root_identity,b.provider_id,b.source_path,h.latest_receipt_id,h.visible_revision_id,h.content_set_digest,h.last_attempt_id,h.update_state FROM source_revision_receipts r LEFT JOIN source_bindings b ON b.source_id=r.source_id LEFT JOIN source_heads h ON h.source_id=r.source_id WHERE r.revision_id=?1").map_err(sql)?;
        let mut rows = statement
            .query([source.revision_id.as_str()])
            .map_err(sql)?;
        let Some(row) = rows.next().map_err(sql)? else {
            return Ok(false);
        };
        let receipt_source =
            SourceId::parse(&row.get::<_, String>(0).map_err(sql)?).map_err(|_| corrupt())?;
        let completeness: String = row.get(1).map_err(sql)?;
        let content_revision: Option<String> = row.get(2).map_err(sql)?;
        let content_digest: Option<String> = row.get(3).map_err(sql)?;
        let committed_at: Option<i64> = row.get(4).map_err(sql)?;
        let parser: i64 = row.get(5).map_err(sql)?;
        let sequence: i64 = row.get(6).map_err(sql)?;
        let reason: Option<String> = row.get(7).map_err(sql)?;
        let root: Option<String> = row.get(8).map_err(sql)?;
        let provider: Option<String> = row.get(9).map_err(sql)?;
        let locator: Option<String> = row.get(10).map_err(sql)?;
        let latest: Option<String> = row.get(11).map_err(sql)?;
        let visible: Option<String> = row.get(12).map_err(sql)?;
        let head_digest: Option<String> = row.get(13).map_err(sql)?;
        let last_attempt: Option<String> = row.get(14).map_err(sql)?;
        let state: Option<String> = row.get(15).map_err(sql)?;
        let revision = self.revision(source.revision_id.as_str())?;
        if parser <= 0
            || sequence <= 0
            || revision.cycle_seq <= 0
            || revision.policy_epoch < 0
            || revision.started_control_seq < 0
            || revision.observed_at_ms < 0
            || revision
                .committed_generation
                .is_some_and(|g| g < 0 || g > self.snapshot.generation)
            || committed_at.is_some_and(|n| n < 0)
            || !matches!(completeness.as_str(), "complete" | "append" | "partial")
            || revision.published != matches!(completeness.as_str(), "complete" | "append")
            || (revision.published
                && (revision.committed_generation.is_none()
                    || committed_at.is_none()
                    || content_revision.is_none()
                    || content_digest.is_none()
                    || reason.is_some()))
        {
            return Err(corrupt());
        }
        for value in [&revision.worker_boot_id, &revision.catalog_incarnation] {
            control::ControlId::parse(value).map_err(|_| corrupt())?;
        }
        checked_label(&revision.digest).map_err(|_| corrupt())?;
        for value in [
            content_revision.as_ref(),
            latest.as_ref(),
            visible.as_ref(),
            last_attempt.as_ref(),
        ]
        .into_iter()
        .flatten()
        {
            RevisionId::parse(value).map_err(|_| corrupt())?;
        }
        let (Some(root), Some(provider), Some(locator), Some(state)) =
            (root, provider, locator, state)
        else {
            return Ok(false);
        };
        // Historical binding evidence only. The current proof is the per
        // selection claim below checked against this selection's own discovery
        // root, which latest_satisfied already bound to current control.
        control::ControlId::parse(&root).map_err(|_| corrupt())?;
        let provider = agent_session_grep_ports::SearchProvider::parse(&provider)
            .filter(|p| p.as_str() == provider)
            .ok_or_else(corrupt)?;
        let locator = control::CanonicalLocator::parse(&locator).map_err(|_| corrupt())?;
        if !matches!(
            state.as_str(),
            "unknown" | "current" | "partial" | "failed" | "deferred" | "paused" | "revoked"
        ) {
            return Err(corrupt());
        }
        if !crate::managed_source_context::receipt_context_current(
            &self.transaction,
            source.revision_id.as_str(),
            self.authorized_policy(),
            self.deadline,
        )? {
            return Ok(false);
        }
        if receipt_source != source.source_id
            || !revision.published
            || revision.cycle_seq != discovery.cycle_seq
            || revision.worker_boot_id != discovery.worker_boot_id
            || revision.catalog_incarnation != discovery.catalog_incarnation
            || revision.policy_epoch != discovery.policy_epoch
            || revision.started_control_seq != discovery.started_control_seq
            || revision
                .committed_generation
                .is_some_and(|g| g > discovery.committed_generation)
            || !selection.region.matches(provider, &locator)
            || latest.as_deref() != Some(source.revision_id.as_str())
            || visible != content_revision
            || head_digest != content_digest
            || last_attempt.as_deref() != Some(source.revision_id.as_str())
            || matches!(
                state.as_str(),
                "partial" | "failed" | "deferred" | "revoked"
            )
        {
            return Ok(false);
        }
        let claim:Option<(i64,String)>=self.transaction.query_row("SELECT selection_revision,root_identity FROM receipt_selection_claims WHERE revision_id=?1 AND selection_id=?2",params![source.revision_id.as_str(),selection.id.as_str()],|r|Ok((r.get(0)?,r.get(1)?))).optional().map_err(sql)?;
        let Some((revision, root)) = claim else {
            return Ok(false);
        };
        if revision < 0 {
            return Err(corrupt());
        }
        control::ControlId::parse(&root).map_err(|_| corrupt())?;
        if revision != discovery.selection_revision || root != discovery.root_identity {
            return Ok(false);
        }
        let scope:Option<(i64,i64)>=self.transaction.query_row("SELECT selection_revision,policy_epoch FROM source_scope_claims WHERE source_id=?1 AND selection_id=?2",params![source.source_id.as_str(),selection.id.as_str()],|r|Ok((r.get(0)?,r.get(1)?))).optional().map_err(sql)?;
        let Some((revision, epoch)) = scope else {
            return Ok(false);
        };
        if revision < 0 || epoch < 0 {
            return Err(corrupt());
        }
        Ok(revision == discovery.selection_revision && epoch == discovery.policy_epoch)
    }

    fn discovery_heads_covered(
        &self,
        sources: &[DiscoverySource],
        discovery: &DiscoveryReceipt,
        selection: &control::Selection,
        policy: &control::ReadPolicy,
    ) -> PortResult<bool> {
        // The proof covers the selection, not just query-matching or already
        // verified sources. A new partial source is absent from allowed_sources.
        let expected: BTreeSet<_> = sources.iter().map(|s| s.source_id.as_str()).collect();
        let mut selected_policy = policy.clone();
        selected_policy.request_intersection = control::RequestIntersection::Selected;
        let mut statement = self.transaction.prepare("SELECT b.source_id,b.provider_id,b.source_path,h.latest_receipt_id,h.last_attempt_id,r.cycle_seq,a.cycle_seq FROM source_bindings b LEFT JOIN source_heads h USING(source_id) LEFT JOIN source_revision_receipts r ON r.revision_id=h.latest_receipt_id AND r.source_id=b.source_id LEFT JOIN source_revision_receipts a ON a.revision_id=h.last_attempt_id AND a.source_id=b.source_id ORDER BY b.source_id").map_err(sql)?;
        let mut rows = statement.query([]).map_err(sql)?;
        while let Some(row) = rows.next().map_err(sql)? {
            self.check_deadline()?;
            let source: String = row.get(0).map_err(sql)?;
            let source_id = control::ControlId::parse(&source).map_err(|_| corrupt())?;
            let provider: String = row.get(1).map_err(sql)?;
            let provider = agent_session_grep_ports::SearchProvider::parse(&provider)
                .filter(|p| p.as_str() == provider)
                .ok_or_else(corrupt)?;
            let locator = control::CanonicalLocator::parse(&row.get::<_, String>(2).map_err(sql)?)
                .map_err(|_| corrupt())?;
            if !crate::managed_source_context::source_read_eligible(&self.transaction, &source)? {
                continue;
            }
            if expected.contains(source.as_str())
                || !selection.region.matches(provider, &locator)
                || !selected_policy.allows_source(provider, &locator, &source_id)
            {
                continue;
            }
            let latest: Option<String> = row.get(3).map_err(sql)?;
            let attempt: Option<String> = row.get(4).map_err(sql)?;
            let completed_cycle: Option<i64> = row.get(5).map_err(sql)?;
            let attempted_cycle: Option<i64> = row.get(6).map_err(sql)?;
            for value in [latest.as_ref(), attempt.as_ref()].into_iter().flatten() {
                RevisionId::parse(value).map_err(|_| corrupt())?;
            }
            if [completed_cycle, attempted_cycle]
                .into_iter()
                .flatten()
                .any(|n| n <= 0)
            {
                return Err(corrupt());
            }
            if (latest.is_some() && completed_cycle.is_none())
                || (attempt.is_some() && attempted_cycle.is_none())
                || attempt.is_none()
                || completed_cycle.is_some_and(|n| n >= discovery.cycle_seq)
                || attempted_cycle.is_some_and(|n| n >= discovery.cycle_seq)
            {
                return Ok(false);
            }
            // Complete discovery cannot silently exclude old readable evidence
            // while claiming that all returned source facts were re-observed.
            let content:bool=self.transaction.query_row("SELECT EXISTS(SELECT 1 FROM source_projections WHERE source_id=?1 UNION ALL SELECT 1 FROM source_occurrences WHERE source_id=?1 UNION ALL SELECT 1 FROM source_entity_projections WHERE source_id=?1)",[&source],|r|r.get(0)).map_err(sql)?;
            if content {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn qualify(&self, query: &ProjectionQuery) -> PortResult<()> {
        self.check_deadline()?;
        if query
            .filters
            .since
            .is_some_and(|v| v.nanosecond >= 1_000_000_000)
            || query
                .filters
                .until
                .is_some_and(|v| v.nanosecond >= 1_000_000_000)
        {
            return Err(invalid());
        }
        let mut clause = String::from(
            "INSERT INTO qualified_occurrences SELECT o.occurrence_rowid FROM source_occurrences o JOIN allowed_sources a USING(source_id) JOIN source_revision_receipts r ON r.revision_id=o.revision_id AND r.source_id=o.source_id JOIN source_heads h ON h.source_id=o.source_id WHERE r.published=1 AND h.visible_revision_id IS NOT NULL AND h.update_state!='revoked'",
        );
        let mut values = Vec::<Value>::new();
        let mut add = |fragment: &str, value: Value| {
            clause.push_str(fragment);
            values.push(value);
        };
        if !query.filters.providers.is_empty() {
            let providers = serde_json::to_string(
                &query
                    .filters
                    .providers
                    .iter()
                    .map(|p| p.as_str())
                    .collect::<Vec<_>>(),
            )
            .map_err(|_| invalid())?;
            add(
                " AND o.provider_id IN (SELECT value FROM json_each(?))",
                providers.into(),
            );
        }
        if let Some(repo) = &query.filters.repo {
            add(
                " AND o.project_id=? AND EXISTS(SELECT 1 FROM source_entity_projections e WHERE e.source_id=o.source_id AND e.entity_id=o.session_id AND e.kind='repo_identity' AND json_extract(e.payload,'$.data.slug')=o.project_id)",
                repo.clone().into(),
            );
        }
        for (bound, op) in [(query.filters.since, ">="), (query.filters.until, "<")] {
            if let Some(bound) = bound {
                add(
                    &format!(" AND (o.instant_unix_seconds,o.instant_nanosecond){op}(?,?)"),
                    bound.unix_seconds.into(),
                );
                // The tuple predicate has two placeholders.
                add("", i64::from(bound.nanosecond).into());
            }
        }
        if let Some(id) = &query.session_id {
            add(" AND o.session_id=?", id.as_str().to_owned().into());
        }
        if !query.include_system {
            clause.push_str(" AND o.role NOT IN ('system','developer')");
        }
        match query.facets.sidechain {
            SidechainFacet::Include => {}
            SidechainFacet::MainOnly => clause.push_str(" AND o.is_sidechain=0"),
            SidechainFacet::SubagentOnly => clause.push_str(" AND o.is_sidechain=1"),
        }
        for (field, value) in [
            ("kind", &query.facets.tool_kind),
            ("name", &query.facets.tool_name),
        ] {
            if let Some(value) = value {
                clause.push_str(&format!(" AND EXISTS(SELECT 1 FROM source_entity_projections e JOIN source_revision_receipts er ON er.revision_id=e.revision_id AND er.source_id=e.source_id WHERE e.source_id=o.source_id AND e.entity_id=o.message_id AND e.kind='tool_activity' AND er.published=1 AND json_extract(e.payload,'$.data.activity.{field}')=?)"));
                values.push(value.clone().into());
            }
        }
        self.transaction
            .execute_batch("DELETE FROM qualified_projections; DELETE FROM qualified_occurrences;")
            .map_err(sql)?;
        self.transaction
            .execute(&clause, rusqlite::params_from_iter(values))
            .map_err(sql)?;
        self.transaction.execute_batch("INSERT INTO qualified_projections SELECT p.projection_rowid FROM source_projections p JOIN allowed_sources a USING(source_id) JOIN source_revision_receipts r ON r.revision_id=p.revision_id AND r.source_id=p.source_id JOIN source_heads h ON h.source_id=p.source_id WHERE r.published=1 AND h.visible_revision_id IS NOT NULL AND h.update_state!='revoked' AND EXISTS(SELECT 1 FROM source_occurrences o JOIN qualified_occurrences q USING(occurrence_rowid) WHERE o.source_id=p.source_id AND o.message_id=p.message_id)").map_err(sql)?;
        Ok(())
    }

    fn revision(&self, id: &str) -> PortResult<RevisionRef> {
        crate::managed_receipt::read_checked(&self.transaction, id, None)
    }
    fn occurrence(&self, source: &str, message: &str) -> PortResult<Option<OccurrenceProjection>> {
        let row:Option<(Vec<u8>,String)>=self.transaction.query_row("SELECT o.payload,o.revision_id FROM source_occurrences o JOIN qualified_occurrences q USING(occurrence_rowid) WHERE source_id=?1 AND message_id=?2 ORDER BY session_id,document_id,source_ordinal,placement_id LIMIT 1",params![source,message],|r|Ok((r.get(0)?,r.get(1)?))).optional().map_err(sql)?;
        row.map(|(payload, revision)| {
            Ok(OccurrenceProjection {
                data: decode(&payload)?,
                source_id: SourceId::parse(source).map_err(|_| corrupt())?,
                revision: self.revision(&revision)?,
            })
        })
        .transpose()
    }
    fn message_row(&self, rowid: i64) -> PortResult<MessageProjection> {
        let (payload,index_text,pd,index_digest,source,id,revision,wire):(Vec<u8>,String,String,String,String,String,String,String)=self.transaction.query_row("SELECT p.payload,p.index_text,p.payload_digest,p.index_digest,p.source_id,p.projection_id,p.revision_id,p.message_id FROM source_projections p JOIN qualified_projections q USING(projection_rowid) WHERE p.projection_rowid=?1",[rowid],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?,r.get(7)?))).map_err(sql)?;
        let message: Message = decode(&payload)?;
        if message.id.as_str() != wire
            || digest(&[&payload]) != pd
            || bounded_index_text(&message.text) != index_text
        {
            return Err(corrupt());
        }
        Ok(MessageProjection {
            message,
            index_text,
            payload_digest: pd,
            index_digest,
            proof: EvidenceProof {
                source_id: SourceId::parse(&source).map_err(|_| corrupt())?,
                projection_id: ProjectionId::parse(&id).map_err(|_| corrupt())?,
                revision: self.revision(&revision)?,
            },
            occurrence: self.occurrence(&source, &wire)?,
        })
    }

    /// Compatibility wrapper over the ranked, same-snapshot metadata channel.
    /// No message snippet or native locator is produced for a metadata hit.
    pub fn search_sessions(
        &self,
        text: &str,
        query: &ProjectionQuery,
        limit: usize,
    ) -> PortResult<Vec<EntityProjection>> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        Ok(self
            .query_session_metadata(text, query, limit.min(512))?
            .hits
            .into_iter()
            .map(|hit| hit.projection)
            .collect())
    }
}
impl Drop for ManagedRead<'_> {
    fn drop(&mut self) {
        let _ = self.transaction.progress_handler(0, None::<fn() -> bool>);
    }
}

impl ProjectionRead for ManagedRead<'_> {
    fn query_session_metadata(
        &self,
        text: &str,
        query: &ProjectionQuery,
        limit: usize,
    ) -> PortResult<SessionMetadataPage> {
        if limit == 0 || limit > 512 {
            return Err(invalid());
        }
        self.qualify_entities(query)?;
        let expression = safe_fts_query(&fts_tokens_cjk(text));
        self.transaction.execute_batch("CREATE TEMP TABLE IF NOT EXISTS qualified_session_metadata(rowid INTEGER PRIMARY KEY) WITHOUT ROWID; DELETE FROM qualified_session_metadata;").map_err(sql)?;
        self.transaction.execute_batch("INSERT INTO qualified_session_metadata SELECT p.session_projection_rowid FROM source_session_projections p JOIN source_entity_projections e ON e.source_id=p.source_id AND e.entity_id=p.session_id AND e.kind='session' JOIN qualified_entities q USING(entity_projection_rowid) JOIN source_revision_receipts r ON r.revision_id=p.revision_id AND r.source_id=p.source_id WHERE r.published=1").map_err(sql)?;
        let removed=self.transaction.execute("DELETE FROM qualified_session_metadata WHERE rowid IN(SELECT p.session_projection_rowid FROM source_session_projections p JOIN qualified_session_metadata q ON q.rowid=p.session_projection_rowid WHERE EXISTS(SELECT 1 FROM source_session_projections other JOIN qualified_session_metadata oq ON oq.rowid=other.session_projection_rowid WHERE other.session_id=p.session_id AND (other.title IS NOT p.title OR other.repo_slug IS NOT p.repo_slug)))",[]).map_err(sql)?;
        // Session titles may derive from the original first user message. The
        // persisted schema deliberately has no fabricated title provenance.
        // If that occurrence is filtered out, omit this metadata variant BEFORE
        // MATCH/statistics/LIMIT. A partial flag records this conservative gap.
        // Ties at the minimum ordinal must all qualify because preparation may
        // have chosen either document's first user message.
        let filtered=self.transaction.execute("DELETE FROM qualified_session_metadata WHERE rowid IN(SELECT p.session_projection_rowid FROM source_session_projections p WHERE EXISTS(SELECT 1 FROM source_occurrences o LEFT JOIN qualified_occurrences q USING(occurrence_rowid) WHERE o.source_id=p.source_id AND o.session_id=p.session_id AND o.role='user' AND o.source_ordinal=(SELECT MIN(first.source_ordinal) FROM source_occurrences first WHERE first.source_id=o.source_id AND first.session_id=o.session_id AND first.role='user') AND q.occurrence_rowid IS NULL))",[]).map_err(sql)?;
        let mut page = SessionMetadataPage {
            hits: Vec::new(),
            truncated: false,
            incomplete: removed > 0 || filtered > 0,
        };
        if expression.is_empty() {
            return Ok(page);
        }
        let (count,total):(i64,i64)=self.transaction.query_row("SELECT COUNT(*),COALESCE(SUM(dl),0) FROM(SELECT p.session_id,p.search_digest,MAX(s.token_count) dl FROM qualified_session_metadata q JOIN source_session_projections p ON p.session_projection_rowid=q.rowid JOIN session_fts_stats s USING(session_projection_rowid) GROUP BY p.session_id,p.search_digest)",[],|r|Ok((r.get(0)?,r.get(1)?))).map_err(sql)?;
        if count < 0 || total < 0 {
            return Err(corrupt());
        }
        if count == 0 || total == 0 {
            return Ok(page);
        }
        let dfs = self.scoped_phrase_counts(
            &expression,
            |phrase, deadline_check| {
                deadline_check()?;
                let df:i64=self.transaction.query_row("SELECT COUNT(*) FROM(SELECT DISTINCT p.session_id,p.search_digest FROM session_metadata_fts JOIN source_session_projections p ON p.session_projection_rowid=session_metadata_fts.rowid JOIN qualified_session_metadata q ON q.rowid=p.session_projection_rowid WHERE session_metadata_fts MATCH ?1)",[phrase],|r|r.get(0)).map_err(sql)?;
                if df < 0 || df > count {
                    return Err(corrupt());
                }
                Ok(df as f64)
            },
        )?;
        let mut statement=self.transaction.prepare("SELECT p.session_projection_rowid,p.session_id,e.payload_digest,p.search_digest,p.source_id,e.projection_id,managed_fts_stats(session_metadata_fts) FROM session_metadata_fts JOIN source_session_projections p ON p.session_projection_rowid=session_metadata_fts.rowid JOIN qualified_session_metadata q ON q.rowid=p.session_projection_rowid JOIN source_entity_projections e ON e.source_id=p.source_id AND e.entity_id=p.session_id AND e.kind='session' WHERE session_metadata_fts MATCH ?1").map_err(sql)?;
        let mut rows = statement.query([&expression]).map_err(sql)?;
        let mut best = BTreeMap::<String, RankedMetadataRow>::new();
        while let Some(row) = rows.next().map_err(sql)? {
            self.check_deadline()?;
            let stats: Vec<u32> = serde_json::from_str(&row.get::<_, String>(6).map_err(sql)?)
                .map_err(|_| corrupt())?;
            let score = scoped_bm25(count, total, &dfs, &stats)?;
            let wire: String = row.get(1).map_err(sql)?;
            let candidate = RankedMetadataRow {
                rowid: row.get(0).map_err(sql)?,
                score,
                tie: (
                    row.get(2).map_err(sql)?,
                    row.get(3).map_err(sql)?,
                    row.get(4).map_err(sql)?,
                    row.get(5).map_err(sql)?,
                ),
            };
            if best.get(&wire).is_none_or(|previous| {
                score > previous.score || (score == previous.score && candidate.tie < previous.tie)
            }) {
                best.insert(wire, candidate);
            }
            if best.len() > limit {
                let worst = best
                    .iter()
                    .min_by(|(wa, a), (wb, b)| a.score.total_cmp(&b.score).then_with(|| wb.cmp(wa)))
                    .map(|(key, _)| key.clone())
                    .ok_or_else(corrupt)?;
                best.remove(&worst);
                page.truncated = true;
            }
        }
        drop(rows);
        drop(statement);
        let mut ordered: Vec<_> = best.into_iter().collect();
        ordered.sort_by(|(wa, a), (wb, b)| b.score.total_cmp(&a.score).then_with(|| wa.cmp(wb)));
        for (_, candidate) in ordered {
            self.check_deadline()?;
            let projection = self.metadata_projection(candidate.rowid)?;
            let EntityData::Session(data) = &projection.data else {
                return Err(corrupt());
            };
            let fields = self.metadata_fields(data, &expression)?;
            page.hits.push(SessionMetadataHit {
                projection,
                score: candidate.score,
                fields,
            });
        }
        Ok(page)
    }
    fn snapshot(&self) -> &ReadSnapshot {
        &self.snapshot
    }
    fn retained_revision_allowed(&self, revision: &RevisionRef) -> PortResult<bool> {
        self.check_deadline()?;
        if self.authorized_policy().is_none() {
            return Ok(false);
        }
        retained_receipt_matches(
            &self.transaction,
            revision,
            &self.snapshot.catalog_incarnation,
            self.snapshot.generation,
        )
    }

    fn session_previews(
        &self,
        requests: &[SessionPreviewRequest],
        query: &ProjectionQuery,
        max_bytes: usize,
    ) -> PortResult<Vec<SessionPreview>> {
        if requests.len() > 512 || max_bytes == 0 || max_bytes > 64 * 1024 * 1024 {
            return Err(invalid());
        }
        self.qualify(query)?;
        let mut remaining = max_bytes;
        let mut result = Vec::new();
        for request in requests {
            self.check_deadline()?;
            if request.session_id.kind() != IdKind::Session || !request.session_id.validate() {
                return Err(invalid());
            }
            let exists:bool=self.transaction.query_row("SELECT EXISTS(SELECT 1 FROM source_entity_projections e JOIN allowed_sources a USING(source_id) JOIN source_revision_receipts r ON r.revision_id=e.revision_id AND r.source_id=e.source_id JOIN source_heads h ON h.source_id=e.source_id WHERE e.source_id=?1 AND e.entity_id=?2 AND e.kind='session' AND r.published=1 AND h.visible_revision_id IS NOT NULL AND h.update_state!='revoked')",params![request.source_id.as_str(),request.session_id.as_str()],|r|r.get(0)).map_err(sql)?;
            let mut preview = SessionPreview {
                request: request.clone(),
                first_user: None,
                last_user: None,
                unavailable: !exists,
            };
            if exists
                && !query
                    .session_id
                    .as_ref()
                    .is_some_and(|s| s.as_str() != request.session_id.as_str())
            {
                for last in [false, true] {
                    match self.preview_endpoint(request, last, &mut remaining) {
                        Ok(message) => {
                            if last {
                                preview.last_user = message
                            } else {
                                preview.first_user = message
                            }
                        }
                        Err(PortError::WriterBusy(_)) => {
                            self.check_deadline()?;
                            preview.unavailable = true;
                            break;
                        }
                        Err(e) => return Err(e),
                    }
                }
            } else {
                preview.unavailable = true;
            }
            result.push(preview);
        }
        Ok(result)
    }
    fn session_graph(
        &self,
        session_id: &StableId,
        query: &ProjectionQuery,
        limits: GraphReadLimits,
    ) -> PortResult<SessionProjectionGraph> {
        if session_id.kind() != IdKind::Session
            || limits.max_occurrences == 0
            || limits.max_occurrences > 16_384
            || limits.max_bytes == 0
            || limits.max_bytes > 64 * 1024 * 1024
        {
            return Err(invalid());
        }
        if query.session_id.as_ref().is_some_and(|id| id != session_id) {
            return Err(graph_not_found());
        }
        let mut scoped = query.clone();
        scoped.session_id = Some(session_id.clone());
        self.qualify(&scoped)?;
        let mut remaining = limits.max_bytes;
        let mut session = None;
        {
            let mut statement=self.transaction.prepare("SELECT e.source_id,length(e.payload) FROM source_entity_projections e JOIN allowed_sources a USING(source_id) JOIN source_revision_receipts r ON r.revision_id=e.revision_id AND r.source_id=e.source_id JOIN source_heads h ON h.source_id=e.source_id WHERE e.kind='session' AND e.entity_id=?1 AND r.published=1 AND h.visible_revision_id IS NOT NULL AND h.update_state!='revoked' ORDER BY e.payload_digest,e.source_id").map_err(sql)?;
            let mut rows = statement.query([session_id.as_str()]).map_err(sql)?;
            while let Some(row) = rows.next().map_err(sql)? {
                self.check_deadline()?;
                let source: String = row.get(0).map_err(sql)?;
                let next = self
                    .graph_entities(
                        &source,
                        EntityKind::Session,
                        session_id.as_str(),
                        false,
                        &mut remaining,
                    )?
                    .into_iter()
                    .next()
                    .ok_or_else(corrupt)?;
                if !self.entity_qualifies(&next.data, &source, session_id.as_str(), &scoped)? {
                    continue;
                }
                // Session identity has one concrete source proof. The consumer
                // derives context membership from the occurrence records.
                session = Some(next);
                break;
            }
        }
        let session = session.ok_or_else(graph_not_found)?;
        let mut occurrences = Vec::new();
        let mut seen = BTreeSet::new();
        let mut statement=self.transaction.prepare("SELECT o.occurrence_rowid,o.placement_id,o.source_id,p.projection_rowid,length(o.payload)+length(p.payload)+length(p.index_text) FROM source_occurrences o JOIN qualified_occurrences q USING(occurrence_rowid) JOIN source_projections p ON p.source_id=o.source_id AND p.message_id=o.message_id JOIN qualified_projections pq ON pq.projection_rowid=p.projection_rowid WHERE o.session_id=?1 ORDER BY o.placement_id,p.payload_digest,p.index_digest,o.source_id,p.projection_id").map_err(sql)?;
        let mut rows = statement.query([session_id.as_str()]).map_err(sql)?;
        while let Some(row) = rows.next().map_err(sql)? {
            self.check_deadline()?;
            let placement: String = row.get(1).map_err(sql)?;
            if !seen.insert(placement.clone()) {
                continue;
            }
            if occurrences.len() == limits.max_occurrences {
                return Err(graph_too_large());
            }
            charge_graph(&mut remaining, row.get(4).map_err(sql)?)?;
            let source: String = row.get(2).map_err(sql)?;
            let rowid: i64 = row.get(0).map_err(sql)?;
            let mut message = self.message_row(row.get(3).map_err(sql)?)?;
            let (payload, revision, payload_digest): (Vec<u8>, String, String) = self
                .transaction
                .query_row(
                    "SELECT payload,revision_id,payload_digest FROM source_occurrences WHERE occurrence_rowid=?1",
                    [rowid],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )
                .map_err(sql)?;
            let data: OccurrenceData = decode(&payload)?;
            if digest(&[&payload]) != payload_digest
                || data.placement.id.as_str() != placement
                || data.placement.session_id != *session_id
                || data.placement.message_id != message.message.id
                || data.role != message.message.role
                || data.timestamp != message.message.timestamp
            {
                return Err(corrupt());
            }
            let mut documents = self.graph_entities(
                &source,
                EntityKind::Document,
                data.placement.source_document_id.as_str(),
                false,
                &mut remaining,
            )?;
            if documents.len() != 1 {
                return Err(corrupt());
            }
            let document_projection = documents.remove(0);
            let EntityData::Document(document) = document_projection.data else {
                return Err(corrupt());
            };
            if document.id != data.placement.source_document_id
                || data.provider_id != document.provider_id
            {
                return Err(corrupt());
            }
            let mut edges = self.graph_entities(
                &source,
                EntityKind::Edge,
                data.placement.id.as_str(),
                true,
                &mut remaining,
            )?;
            if edges.len() > 1 {
                return Err(corrupt());
            }
            let edge = edges.pop();
            if let Some(edge) = &edge
                && !matches!(&edge.data,EntityData::Edge{child,..} if *child==data.placement.id)
            {
                return Err(corrupt());
            }
            let tools = self.graph_entities(
                &source,
                EntityKind::Tool,
                message.message.id.as_str(),
                false,
                &mut remaining,
            )?;
            message.occurrence = Some(OccurrenceProjection {
                data,
                source_id: SourceId::parse(&source).map_err(|_| corrupt())?,
                revision: self.revision(&revision)?,
            });
            occurrences.push(ContextProjection {
                message,
                document,
                document_proof: document_projection.proof,
                edge,
                tools,
            });
        }
        let visible: BTreeSet<_> = occurrences
            .iter()
            .map(|o| o.message.message.id.as_str().to_owned())
            .collect();
        for occurrence in &mut occurrences {
            if occurrence.edge.as_ref().is_some_and(|p|matches!(&p.data,EntityData::Edge{parent,..} if !visible.contains(parent.as_str()))){occurrence.edge=None;}
        }
        Ok(SessionProjectionGraph {
            session,
            occurrences,
        })
    }
    fn message_contexts(
        &self,
        message_id: &StableId,
        query: &ProjectionQuery,
        max_candidates: usize,
        max_occurrences: usize,
    ) -> PortResult<MessageContextsPage> {
        if message_id.kind() != IdKind::Message
            || max_candidates == 0
            || max_candidates > 512
            || max_occurrences == 0
            || max_occurrences > 16_384
        {
            return Err(invalid());
        }
        self.qualify(query)?;
        let count:i64=self.transaction.query_row("SELECT COUNT(DISTINCT o.session_id) FROM source_occurrences o JOIN qualified_occurrences q USING(occurrence_rowid) WHERE o.message_id=?1",[message_id.as_str()],|r|r.get(0)).map_err(sql)?;
        if count == 0 {
            return Err(graph_not_found());
        }
        let mut candidates = Vec::<ProjectedMessageContext>::new();
        let mut total = 0;
        let mut truncated = false;
        let mut remaining = GraphReadLimits::default().max_bytes;
        let mut statement=self.transaction.prepare("SELECT o.session_id,o.placement_id,o.payload,o.source_id,o.revision_id,p.projection_id,p.revision_id,length(o.payload),o.payload_digest FROM source_occurrences o JOIN qualified_occurrences q USING(occurrence_rowid) JOIN source_projections p ON p.source_id=o.source_id AND p.message_id=o.message_id JOIN qualified_projections pq ON pq.projection_rowid=p.projection_rowid WHERE o.message_id=?1 ORDER BY o.session_id,o.placement_id,p.payload_digest,p.index_digest,o.source_id,p.projection_id").map_err(sql)?;
        let mut rows = statement.query([message_id.as_str()]).map_err(sql)?;
        let mut previous = None;
        while let Some(row) = rows.next().map_err(sql)? {
            self.check_deadline()?;
            let session: String = row.get(0).map_err(sql)?;
            let placement: String = row.get(1).map_err(sql)?;
            if previous.as_ref() == Some(&(session.clone(), placement.clone())) {
                continue;
            }
            previous = Some((session.clone(), placement.clone()));
            let new_session = candidates
                .last()
                .is_none_or(|c| c.session_id.as_str() != session);
            if total == max_occurrences || (new_session && candidates.len() == max_candidates) {
                truncated = true;
                break;
            }
            charge_graph(&mut remaining, row.get(7).map_err(sql)?)?;
            let payload: Vec<u8> = row.get(2).map_err(sql)?;
            let data: OccurrenceData = decode(&payload)?;
            if digest(&[&payload]) != row.get::<_, String>(8).map_err(sql)?
                || data.placement.id.as_str() != placement
                || data.placement.message_id != *message_id
                || data.placement.session_id.as_str() != session
            {
                return Err(corrupt());
            }
            if new_session {
                candidates.push(ProjectedMessageContext {
                    session_id: data.placement.session_id.clone(),
                    occurrences: Vec::new(),
                });
            }
            let occurrence = OccurrenceProjection {
                data,
                source_id: SourceId::parse(&row.get::<_, String>(3).map_err(sql)?)
                    .map_err(|_| corrupt())?,
                revision: self.revision(&row.get::<_, String>(4).map_err(sql)?)?,
            };
            let proof = EvidenceProof {
                source_id: occurrence.source_id.clone(),
                projection_id: ProjectionId::parse(&row.get::<_, String>(5).map_err(sql)?)
                    .map_err(|_| corrupt())?,
                revision: self.revision(&row.get::<_, String>(6).map_err(sql)?)?,
            };
            candidates
                .last_mut()
                .ok_or_else(corrupt)?
                .occurrences
                .push(OccurrenceEvidence { occurrence, proof });
            total += 1;
        }
        Ok(MessageContextsPage {
            candidates,
            candidate_count: u64::try_from(count).map_err(|_| corrupt())?,
            truncated,
        })
    }
    fn source_progress(&self) -> PortResult<Vec<SourceProgress>> {
        self.check_deadline()?;
        let mut statement=self.transaction.prepare("SELECT h.source_id,h.visible_revision_id,h.latest_receipt_id,h.last_attempt_id FROM source_heads h JOIN allowed_sources a USING(source_id) ORDER BY h.source_id").map_err(sql)?;
        let mut rows = statement.query([]).map_err(sql)?;
        let mut result = Vec::new();
        while let Some(row) = rows.next().map_err(sql)? {
            self.check_deadline()?;
            let visible: Option<String> = row.get(1).map_err(sql)?;
            let latest: Option<String> = row.get(2).map_err(sql)?;
            let attempt: Option<String> = row.get(3).map_err(sql)?;
            result.push(SourceProgress {
                source_id: SourceId::parse(&row.get::<_, String>(0).map_err(sql)?)
                    .map_err(|_| corrupt())?,
                visible_revision: visible
                    .map(|id| RevisionId::parse(&id).map_err(|_| corrupt()))
                    .transpose()?,
                latest_receipt: latest.map(|id| self.revision(&id)).transpose()?,
                last_attempt: attempt.map(|id| self.revision(&id)).transpose()?,
            });
        }
        Ok(result)
    }
    fn list(
        &self,
        query: &ProjectionQuery,
        sessions_only: bool,
        limit: usize,
    ) -> PortResult<ProjectionListPage> {
        if limit == 0 || limit > 512 {
            return Err(invalid());
        }
        self.qualify_entities(query)?;
        let mut entries = Vec::new();
        let mut after = String::new();
        loop {
            // Close the enumeration statement before enrichment rebuilds the
            // request-local qualification tables. Keyset pages bound ID memory.
            let ids = {
                let mut statement=self.transaction.prepare("SELECT id FROM(SELECT entity_id id FROM source_entity_projections e JOIN qualified_entities q USING(entity_projection_rowid) WHERE e.kind IN ('session','document') AND (?1=0 OR e.kind='session') UNION SELECT p.message_id FROM source_projections p JOIN qualified_projections q USING(projection_rowid) WHERE ?1=0) WHERE id>?2 ORDER BY id LIMIT 128").map_err(sql)?;
                statement
                    .query_map(params![sessions_only, after], |row| row.get::<_, String>(0))
                    .map_err(sql)?
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(sql)?
            };
            if ids.is_empty() {
                break;
            }
            for wire in ids {
                self.check_deadline()?;
                after = wire.clone();
                let id = StableId::from_wire(&wire).ok_or_else(corrupt)?;
                let next = match id.kind() {
                    IdKind::Message => self
                        .messages(std::slice::from_ref(&id), query)?
                        .pop()
                        .flatten()
                        .map(|p| ProjectionListEntry::Message(Box::new(p))),
                    IdKind::Session | IdKind::Document => self
                        .entities(
                            if id.kind() == IdKind::Session {
                                EntityKind::Session
                            } else {
                                EntityKind::Document
                            },
                            std::slice::from_ref(&id),
                            query,
                        )?
                        .into_iter()
                        .next()
                        .map(|p| ProjectionListEntry::Entity(Box::new(p))),
                    _ => return Err(corrupt()),
                };
                if let Some(next) = next {
                    if entries.len() == limit {
                        return Ok(ProjectionListPage {
                            entries,
                            truncated: true,
                        });
                    }
                    entries.push(next);
                }
            }
        }
        Ok(ProjectionListPage {
            entries,
            truncated: false,
        })
    }
    fn stats(&self, query: &ProjectionQuery, repo_limit: usize) -> PortResult<ProjectionStats> {
        if repo_limit == 0 || repo_limit > 512 {
            return Err(invalid());
        }
        self.qualify_entities(query)?;
        let catalog_count:i64=self.transaction.query_row("SELECT COUNT(*) FROM(SELECT message_id FROM source_projections p JOIN qualified_projections q USING(projection_rowid) UNION SELECT entity_id FROM source_entity_projections e JOIN qualified_entities q USING(entity_projection_rowid) WHERE kind IN('session','document'))",[],|r|r.get(0)).map_err(sql)?;
        let (placements,claims):(i64,i64)=self.transaction.query_row("SELECT COUNT(DISTINCT o.placement_id),COUNT(*) FROM source_occurrences o JOIN qualified_occurrences q USING(occurrence_rowid)",[],|r|Ok((r.get(0)?,r.get(1)?))).map_err(sql)?;
        let mut statement=self.transaction.prepare("SELECT e.entity_key,e.payload FROM source_entity_projections e JOIN qualified_entities q USING(entity_projection_rowid) WHERE e.kind='usage_event' ORDER BY e.entity_key,e.payload_digest,e.source_id").map_err(sql)?;
        let mut rows = statement.query([]).map_err(sql)?;
        let mut usage = agent_session_grep_ports::UsageTotals::default();
        let mut current: Option<(String, EntityData, bool)> = None;
        let mut facts_incomplete = false;
        let mut had_usage = false;
        self.transaction.execute_batch("CREATE TEMP TABLE IF NOT EXISTS managed_usage_sessions(session_id TEXT PRIMARY KEY) WITHOUT ROWID; DELETE FROM managed_usage_sessions;").map_err(sql)?;
        let mut consume = |item: Option<(String, EntityData, bool)>| -> PortResult<()> {
            let Some((
                _,
                EntityData::Usage {
                    session_id,
                    usage: observed,
                    ..
                },
                conflict,
            )) = item
            else {
                return Ok(());
            };
            if conflict {
                facts_incomplete = true;
                return Ok(());
            }
            had_usage = true;
            self.transaction
                .execute(
                    "INSERT OR IGNORE INTO managed_usage_sessions VALUES(?1)",
                    [session_id.as_str()],
                )
                .map_err(sql)?;
            for (total, value) in [
                (&mut usage.input_tokens, observed.input_tokens),
                (&mut usage.output_tokens, observed.output_tokens),
                (&mut usage.cache_read_tokens, observed.cache_read_tokens),
                (&mut usage.cache_write_tokens, observed.cache_write_tokens),
                (&mut usage.reasoning_tokens, observed.reasoning_tokens),
            ] {
                *total = total.checked_add(value).ok_or_else(corrupt)?;
            }
            let count = match observed.token_source {
                agent_session_grep_domain::TokenSource::Observed => &mut usage.observed_events,
                agent_session_grep_domain::TokenSource::Derived => &mut usage.derived_events,
            };
            *count = count.checked_add(1).ok_or_else(corrupt)?;
            Ok(())
        };
        while let Some(row) = rows.next().map_err(sql)? {
            self.check_deadline()?;
            let key: String = row.get(0).map_err(sql)?;
            let data: EntityData = decode(&row.get::<_, Vec<u8>>(1).map_err(sql)?)?;
            if !matches!(data, EntityData::Usage { .. }) {
                return Err(corrupt());
            }
            if let Some((prior, first, conflict)) = &mut current
                && *prior == key
            {
                *conflict |= *first != data;
                continue;
            }
            consume(current.take())?;
            current = Some((key, data, false));
        }
        consume(current)?;
        let usage_sessions: i64 = self
            .transaction
            .query_row("SELECT COUNT(*) FROM managed_usage_sessions", [], |r| {
                r.get(0)
            })
            .map_err(sql)?;
        usage.sessions = u64::try_from(usage_sessions).map_err(|_| corrupt())?;
        let mut statement=self.transaction.prepare("SELECT json_extract(e.payload,'$.data.slug'),COUNT(DISTINCT e.entity_id) FROM source_entity_projections e JOIN qualified_entities q USING(entity_projection_rowid) WHERE e.kind='repo_identity' AND NOT EXISTS(SELECT 1 FROM source_entity_projections other JOIN qualified_entities oq ON oq.entity_projection_rowid=other.entity_projection_rowid WHERE other.kind='repo_identity' AND other.entity_id=e.entity_id AND other.payload_digest!=e.payload_digest) GROUP BY json_extract(e.payload,'$.data.slug') ORDER BY 1 LIMIT ?1").map_err(sql)?;
        let repo_rows = statement
            .query_map(
                [i64::try_from(repo_limit + 1).map_err(|_| invalid())?],
                |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)),
            )
            .map_err(sql)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(sql)?;
        let mut repos = repo_rows
            .into_iter()
            .map(|(repo_slug, sessions)| {
                Ok(agent_session_grep_ports::RepoTotals {
                    repo_slug,
                    sessions: u64::try_from(sessions).map_err(|_| corrupt())?,
                })
            })
            .collect::<PortResult<Vec<_>>>()?;
        let repos_truncated = repos.len() > repo_limit;
        repos.truncate(repo_limit);
        let repo_conflict:bool=self.transaction.query_row("SELECT EXISTS(SELECT 1 FROM source_entity_projections e JOIN qualified_entities q USING(entity_projection_rowid) JOIN source_entity_projections other ON other.entity_id=e.entity_id AND other.kind=e.kind JOIN qualified_entities oq ON oq.entity_projection_rowid=other.entity_projection_rowid WHERE e.kind='repo_identity' AND e.payload_digest!=other.payload_digest)",[],|r|r.get(0)).map_err(sql)?;
        Ok(ProjectionStats {
            catalog_count: u64::try_from(catalog_count).map_err(|_| corrupt())?,
            placements: u64::try_from(placements).map_err(|_| corrupt())?,
            source_placement_claims: u64::try_from(claims).map_err(|_| corrupt())?,
            usage: had_usage.then_some(usage),
            repos,
            repos_truncated,
            facts_incomplete: facts_incomplete || repo_conflict,
        })
    }
    fn messages(
        &self,
        ids: &[StableId],
        query: &ProjectionQuery,
    ) -> PortResult<Vec<Option<MessageProjection>>> {
        self.qualify(query)?;
        let mut result = Vec::with_capacity(ids.len());
        let mut stmt=self.transaction.prepare("SELECT p.projection_rowid FROM source_projections p JOIN qualified_projections q USING(projection_rowid) WHERE message_id=?1 ORDER BY payload_digest,index_digest,source_id LIMIT 1").map_err(sql)?;
        for id in ids {
            self.check_deadline()?;
            let row = stmt
                .query_row([id.as_str()], |r| r.get(0))
                .optional()
                .map_err(sql)?;
            result.push(row.map(|row| self.message_row(row)).transpose()?);
        }
        Ok(result)
    }
    fn occurrences(
        &self,
        ids: &[StableId],
        query: &ProjectionQuery,
    ) -> PortResult<Vec<OccurrenceProjection>> {
        self.qualify(query)?;
        let ids = serde_json::to_string(&ids.iter().map(StableId::as_str).collect::<Vec<_>>())
            .map_err(|_| invalid())?;
        let mut statement=self.transaction.prepare("SELECT o.payload,o.source_id,o.revision_id FROM source_occurrences o JOIN qualified_occurrences q USING(occurrence_rowid) WHERE message_id IN(SELECT value FROM json_each(?1)) ORDER BY message_id,session_id,document_id,source_ordinal,source_id").map_err(sql)?;
        let mut rows = statement.query([ids]).map_err(sql)?;
        let mut result = Vec::new();
        while let Some(row) = rows.next().map_err(sql)? {
            self.check_deadline()?;
            result.push(OccurrenceProjection {
                data: decode(&row.get::<_, Vec<u8>>(0).map_err(sql)?)?,
                source_id: SourceId::parse(&row.get::<_, String>(1).map_err(sql)?)
                    .map_err(|_| corrupt())?,
                revision: self.revision(&row.get::<_, String>(2).map_err(sql)?)?,
            });
        }
        Ok(result)
    }
    fn entities(
        &self,
        kind: EntityKind,
        ids: &[StableId],
        query: &ProjectionQuery,
    ) -> PortResult<Vec<EntityProjection>> {
        self.qualify(query)?;
        let id_json = serde_json::to_string(&ids.iter().map(StableId::as_str).collect::<Vec<_>>())
            .map_err(|_| invalid())?;
        let mut statement=self.transaction.prepare("SELECT e.payload,e.source_id,e.projection_id,e.revision_id,e.entity_key,e.entity_id FROM source_entity_projections e JOIN allowed_sources a USING(source_id) JOIN source_revision_receipts r ON r.revision_id=e.revision_id AND r.source_id=e.source_id JOIN source_heads h ON h.source_id=e.source_id WHERE e.kind=?1 AND e.entity_id IN(SELECT value FROM json_each(?2)) AND r.published=1 AND h.visible_revision_id IS NOT NULL AND h.update_state!='revoked' ORDER BY e.entity_key,e.payload_digest,e.source_id").map_err(sql)?;
        let mut rows = statement
            .query(params![kind.as_str(), id_json])
            .map_err(sql)?;
        let mut groups = BTreeMap::<String, Vec<EntityProjection>>::new();
        while let Some(row) = rows.next().map_err(sql)? {
            self.check_deadline()?;
            let data: EntityData = decode(&row.get::<_, Vec<u8>>(0).map_err(sql)?)?;
            let source: String = row.get(1).map_err(sql)?;
            let entity_id: String = row.get(5).map_err(sql)?;
            if !self.entity_qualifies(&data, &source, &entity_id, query)? {
                continue;
            }
            let projection = EntityProjection {
                data,
                proof: EvidenceProof {
                    source_id: SourceId::parse(&source).map_err(|_| corrupt())?,
                    projection_id: ProjectionId::parse(&row.get::<_, String>(2).map_err(sql)?)
                        .map_err(|_| corrupt())?,
                    revision: self.revision(&row.get::<_, String>(3).map_err(sql)?)?,
                },
            };
            groups
                .entry(row.get(4).map_err(sql)?)
                .or_default()
                .push(projection);
        }
        let mut result = Vec::new();
        for (_, mut group) in groups {
            let representative = group.remove(0);
            // Safe metadata can be unavailable on conflict; native resume and
            // conflicting fact payloads are omitted rather than source-picked.
            if let EntityData::Session(session) = &representative.data {
                let title_conflict = group.iter().any(
                    |p| !matches!(&p.data,EntityData::Session(other) if other.title==session.title),
                );
                let repo_conflict=group.iter().any(|p|!matches!(&p.data,EntityData::Session(other) if other.repo_slug==session.repo_slug));
                // Keep per-source document sets with their own proof. A union
                // attributed to one arbitrary source would fabricate provenance.
                group.insert(0, representative);
                for mut projection in group {
                    if let EntityData::Session(data) = &mut projection.data {
                        if title_conflict {
                            data.title = None;
                        }
                        if repo_conflict {
                            data.repo_slug = None;
                        }
                    }
                    result.push(projection);
                }
                continue;
            } else if group.iter().any(|other| other.data != representative.data) {
                continue;
            }
            result.push(representative);
        }
        Ok(result)
    }
    fn query_lexical(
        &self,
        text: &str,
        query: &ProjectionQuery,
        limit: usize,
    ) -> PortResult<LexicalPage> {
        self.qualify(query)?;
        let expression = safe_fts_query(&fts_tokens_cjk(text));
        if expression.is_empty() || limit == 0 {
            return Ok(LexicalPage {
                hits: Vec::new(),
                truncated: false,
            });
        }
        let (count,total):(i64,i64)=self.transaction.query_row("SELECT COUNT(*),COALESCE(SUM(dl),0) FROM(SELECT p.message_id,p.index_digest,MAX(s.token_count) dl FROM qualified_projections q JOIN source_projections p USING(projection_rowid) JOIN projection_fts_stats s USING(projection_rowid) GROUP BY p.message_id,p.index_digest)",[],|r|Ok((r.get(0)?,r.get(1)?))).map_err(sql)?;
        if count == 0 || total == 0 {
            return Ok(LexicalPage {
                hits: Vec::new(),
                truncated: false,
            });
        }
        let dfs = self.scoped_phrase_counts(
            &expression,
            |phrase, deadline_check| {
                deadline_check()?;
                let df:i64=self.transaction.query_row("SELECT COUNT(*) FROM(SELECT DISTINCT p.message_id,p.index_digest FROM projection_fts JOIN source_projections p ON p.projection_rowid=projection_fts.rowid JOIN qualified_projections q USING(projection_rowid) WHERE projection_fts MATCH ?1)",[phrase],|r|r.get(0)).map_err(sql)?;
                Ok(df as f64)
            },
        )?;
        struct Candidate {
            rowid: i64,
            score: f64,
            tie: (String, String, String, String),
        }
        let mut best = BTreeMap::<String, Candidate>::new();
        let mut statement=self.transaction.prepare("SELECT p.projection_rowid,p.message_id,p.payload_digest,p.index_digest,p.source_id,p.projection_id,managed_fts_stats(projection_fts) FROM projection_fts JOIN source_projections p ON p.projection_rowid=projection_fts.rowid JOIN qualified_projections q USING(projection_rowid) WHERE projection_fts MATCH ?1").map_err(sql)?;
        let mut rows = statement.query([expression]).map_err(sql)?;
        let capacity = limit.min(512);
        let mut truncated = false;
        while let Some(row) = rows.next().map_err(sql)? {
            self.check_deadline()?;
            let stats: Vec<u32> = serde_json::from_str(&row.get::<_, String>(6).map_err(sql)?)
                .map_err(|_| corrupt())?;
            let score = scoped_bm25(count, total, &dfs, &stats)?;
            let wire: String = row.get(1).map_err(sql)?;
            let candidate = Candidate {
                rowid: row.get(0).map_err(sql)?,
                score,
                tie: (
                    row.get(2).map_err(sql)?,
                    row.get(3).map_err(sql)?,
                    row.get(4).map_err(sql)?,
                    row.get(5).map_err(sql)?,
                ),
            };
            let replace = best.get(&wire).is_none_or(|previous| {
                score > previous.score || (score == previous.score && candidate.tie < previous.tie)
            });
            if replace {
                best.insert(wire, candidate);
            }
            if best.len() > capacity {
                let worst = best
                    .iter()
                    .min_by(|(wa, a), (wb, b)| a.score.total_cmp(&b.score).then_with(|| wb.cmp(wa)))
                    .map(|(key, _)| key.clone())
                    .ok_or_else(corrupt)?;
                best.remove(&worst);
                truncated = true;
            }
        }
        let mut ordered: Vec<_> = best.into_iter().collect();
        ordered.sort_by(|(wa, a), (wb, b)| b.score.total_cmp(&a.score).then_with(|| wa.cmp(wb)));
        let mut hits = Vec::new();
        for (wire, candidate) in ordered {
            self.check_deadline()?;
            let claims:i64=self.transaction.query_row("SELECT COUNT(*) FROM source_projections p JOIN qualified_projections q USING(projection_rowid) WHERE message_id=?1",[wire],|r|r.get(0)).map_err(sql)?;
            hits.push(LexicalHit {
                projection: self.message_row(candidate.rowid)?,
                score: candidate.score,
                claim_count: usize::try_from(claims).map_err(|_| corrupt())?,
            });
        }
        Ok(LexicalPage { hits, truncated })
    }
}

impl ManagedRead<'_> {
    fn metadata_projection(&self, rowid: i64) -> PortResult<EntityProjection> {
        let row = self.transaction.query_row("SELECT e.payload,e.payload_digest,e.source_id,e.projection_id,e.revision_id,p.search_text,p.search_digest FROM source_session_projections p JOIN source_entity_projections e ON e.source_id=p.source_id AND e.entity_id=p.session_id AND e.kind='session' JOIN qualified_session_metadata q ON q.rowid=p.session_projection_rowid WHERE p.session_projection_rowid=?1",[rowid],|r|Ok(MetadataRow {
            payload:r.get(0)?, payload_digest:r.get(1)?, source:r.get(2)?,
            projection:r.get(3)?, revision:r.get(4)?, search_text:r.get(5)?, search_digest:r.get(6)?
        })).map_err(sql)?;
        if digest(&[&row.payload]) != row.payload_digest
            || digest(&[row.search_text.as_bytes()]) != row.search_digest
        {
            return Err(corrupt());
        }
        let data: EntityData = decode(&row.payload)?;
        let EntityData::Session(session) = &data else {
            return Err(corrupt());
        };
        let expected = bounded_index_text(
            &[
                session.title.as_deref().unwrap_or(""),
                session.repo_slug.as_deref().unwrap_or(""),
                &session.provider_id,
                session.first_user_text.as_deref().unwrap_or(""),
            ]
            .join("\n"),
        );
        if expected != row.search_text {
            return Err(corrupt());
        }
        Ok(EntityProjection {
            data,
            proof: EvidenceProof {
                source_id: SourceId::parse(&row.source).map_err(|_| corrupt())?,
                projection_id: ProjectionId::parse(&row.projection).map_err(|_| corrupt())?,
                revision: self.revision(&row.revision)?,
            },
        })
    }

    fn metadata_fields(
        &self,
        data: &SessionData,
        expression: &str,
    ) -> PortResult<Vec<SessionMetadataField>> {
        // The same FTS tokenizer/query grammar proves field attribution. This
        // four-row temporary matcher never persists content or native locators.
        self.transaction.execute_batch("CREATE VIRTUAL TABLE IF NOT EXISTS temp.metadata_field_match USING fts5(text,tokenize='unicode61'); DELETE FROM metadata_field_match;").map_err(sql)?;
        let fields = [
            (
                SessionMetadataField::Title,
                data.title.as_deref().unwrap_or(""),
            ),
            (
                SessionMetadataField::Repository,
                data.repo_slug.as_deref().unwrap_or(""),
            ),
            (SessionMetadataField::Provider, data.provider_id.as_str()),
            (
                SessionMetadataField::FirstUser,
                data.first_user_text.as_deref().unwrap_or(""),
            ),
        ];
        for (i, (_, text)) in fields.iter().enumerate() {
            self.transaction
                .execute(
                    "INSERT INTO metadata_field_match(rowid,text) VALUES(?1,?2)",
                    params![i as i64 + 1, fts_tokens_cjk(text)],
                )
                .map_err(sql)?;
        }
        let mut result = BTreeSet::new();
        for phrase in fts_clauses(expression)? {
            self.check_deadline()?;
            let mut stmt=self.transaction.prepare("SELECT rowid FROM metadata_field_match WHERE metadata_field_match MATCH ?1 ORDER BY rowid").map_err(sql)?;
            let ids = stmt
                .query_map([phrase], |r| r.get::<_, i64>(0))
                .map_err(sql)?;
            for id in ids {
                let index = usize::try_from(id.map_err(sql)? - 1).map_err(|_| corrupt())?;
                if index >= fields.len() {
                    return Err(corrupt());
                }
                result.insert(index);
            }
        }
        self.transaction
            .execute("DELETE FROM metadata_field_match", [])
            .map_err(sql)?;
        Ok(result.into_iter().map(|i| fields[i].0).collect())
    }
    fn preview_endpoint(
        &self,
        request: &SessionPreviewRequest,
        last: bool,
        remaining: &mut usize,
    ) -> PortResult<Option<PreviewMessage>> {
        let order = if last { "DESC" } else { "ASC" };
        let mut stmt=self.transaction.prepare(&format!("SELECT p.projection_rowid,o.payload,o.payload_digest,o.revision_id,length(p.payload)+length(o.payload)+length(p.index_text) FROM source_occurrences o JOIN qualified_occurrences q USING(occurrence_rowid) JOIN source_projections p ON p.source_id=o.source_id AND p.message_id=o.message_id JOIN qualified_projections qp USING(projection_rowid) WHERE o.source_id=?1 AND o.session_id=?2 AND o.role='user' ORDER BY o.document_id {order},o.source_ordinal {order},o.placement_id {order}")).map_err(sql)?;
        let mut rows = stmt
            .query(params![
                request.source_id.as_str(),
                request.session_id.as_str()
            ])
            .map_err(sql)?;
        while let Some(row) = rows.next().map_err(sql)? {
            self.check_deadline()?;
            charge_graph(remaining, row.get(4).map_err(sql)?)?;
            let payload: Vec<u8> = row.get(1).map_err(sql)?;
            if digest(&[&payload]) != row.get::<_, String>(2).map_err(sql)? {
                return Err(corrupt());
            }
            let occurrence: OccurrenceData = decode(&payload)?;
            let message = self.message_row(row.get(0).map_err(sql)?)?;
            if occurrence.placement.session_id.as_str() != request.session_id.as_str()
                || occurrence.placement.message_id.as_str() != message.message.id.as_str()
                || occurrence.role != Role::User
                || message.message.role != Role::User
                || occurrence.timestamp != message.message.timestamp
                || message.proof.source_id != request.source_id
            {
                return Err(corrupt());
            }
            if message.message.text.trim().is_empty() {
                continue;
            }
            return Ok(Some(PreviewMessage {
                text: message
                    .message
                    .text
                    .trim()
                    .chars()
                    .take(agent_session_grep_application::peek::PEEK_FIELD_MAX_CHARS)
                    .collect(),
                occurrence: OccurrenceProjection {
                    data: occurrence,
                    source_id: request.source_id.clone(),
                    revision: self.revision(&row.get::<_, String>(3).map_err(sql)?)?,
                },
                proof: message.proof,
            }));
        }
        Ok(None)
    }
    fn graph_entities(
        &self,
        source: &str,
        kind: EntityKind,
        key: &str,
        by_key: bool,
        remaining: &mut usize,
    ) -> PortResult<Vec<EntityProjection>> {
        let column = if by_key { "entity_key" } else { "entity_id" };
        let mut statement=self.transaction.prepare(&format!("SELECT e.payload,e.payload_digest,e.projection_id,e.revision_id,length(e.payload) FROM source_entity_projections e JOIN allowed_sources a USING(source_id) JOIN source_revision_receipts r ON r.revision_id=e.revision_id AND r.source_id=e.source_id WHERE e.source_id=?1 AND e.kind=?2 AND e.{column}=?3 AND r.published=1 ORDER BY e.entity_key")).map_err(sql)?;
        let mut rows = statement
            .query(params![source, kind.as_str(), key])
            .map_err(sql)?;
        let mut result = Vec::new();
        while let Some(row) = rows.next().map_err(sql)? {
            self.check_deadline()?;
            charge_graph(remaining, row.get(4).map_err(sql)?)?;
            let payload: Vec<u8> = row.get(0).map_err(sql)?;
            let expected: String = row.get(1).map_err(sql)?;
            if digest(&[&payload]) != expected {
                return Err(corrupt());
            }
            result.push(EntityProjection {
                data: decode(&payload)?,
                proof: EvidenceProof {
                    source_id: SourceId::parse(source).map_err(|_| corrupt())?,
                    projection_id: ProjectionId::parse(&row.get::<_, String>(2).map_err(sql)?)
                        .map_err(|_| corrupt())?,
                    revision: self.revision(&row.get::<_, String>(3).map_err(sql)?)?,
                },
            });
        }
        Ok(result)
    }
    fn qualify_entities(&self, query: &ProjectionQuery) -> PortResult<()> {
        self.qualify(query)?;
        self.transaction.execute_batch("CREATE TEMP TABLE IF NOT EXISTS qualified_entities(entity_projection_rowid INTEGER PRIMARY KEY) WITHOUT ROWID; DELETE FROM qualified_entities;").map_err(sql)?;
        let mut statement=self.transaction.prepare("SELECT e.entity_projection_rowid,e.payload,e.source_id,e.entity_id FROM source_entity_projections e JOIN allowed_sources a USING(source_id) JOIN source_revision_receipts r ON r.revision_id=e.revision_id AND r.source_id=e.source_id JOIN source_heads h ON h.source_id=e.source_id WHERE r.published=1 AND h.visible_revision_id IS NOT NULL AND h.update_state!='revoked'").map_err(sql)?;
        let mut rows = statement.query([]).map_err(sql)?;
        while let Some(row) = rows.next().map_err(sql)? {
            self.check_deadline()?;
            let data: EntityData = decode(&row.get::<_, Vec<u8>>(1).map_err(sql)?)?;
            if self.entity_qualifies(
                &data,
                &row.get::<_, String>(2).map_err(sql)?,
                &row.get::<_, String>(3).map_err(sql)?,
                query,
            )? {
                self.transaction
                    .execute(
                        "INSERT INTO qualified_entities VALUES(?1)",
                        [row.get::<_, i64>(0).map_err(sql)?],
                    )
                    .map_err(sql)?;
            }
        }
        Ok(())
    }
    fn entity_qualifies(
        &self,
        data: &EntityData,
        source: &str,
        id: &str,
        query: &ProjectionQuery,
    ) -> PortResult<bool> {
        let column = match data {
            EntityData::Document(_) => "document_id",
            EntityData::Tool { .. }
            | EntityData::Edge { .. }
            | EntityData::Usage {
                message_id: Some(_),
                ..
            } => "message_id",
            _ => "session_id",
        };
        let anchor = if let EntityData::Usage {
            message_id: Some(message),
            ..
        } = data
        {
            message.as_str()
        } else {
            id
        };
        let exists:bool=self.transaction.query_row(&format!("SELECT EXISTS(SELECT 1 FROM source_occurrences o JOIN qualified_occurrences q USING(occurrence_rowid) WHERE o.source_id=?1 AND o.{column}=?2)"),params![source,anchor],|r|r.get(0)).map_err(sql)?;
        if let EntityData::Edge { parent, child, .. } = data {
            let visible:bool=self.transaction.query_row("SELECT EXISTS(SELECT 1 FROM source_projections p JOIN qualified_projections q USING(projection_rowid) WHERE message_id=?1)",[parent.as_str()],|r|r.get(0)).map_err(sql)?;
            let child_visible:bool=self.transaction.query_row("SELECT EXISTS(SELECT 1 FROM source_occurrences o JOIN qualified_occurrences q USING(occurrence_rowid) WHERE o.source_id=?1 AND o.placement_id=?2)",params![source,child.as_str()],|r|r.get(0)).map_err(sql)?;
            return Ok(child_visible && visible);
        }
        if exists {
            return Ok(true);
        }
        let has_occurrences:bool=self.transaction.query_row(&format!("SELECT EXISTS(SELECT 1 FROM source_occurrences WHERE source_id=?1 AND {column}=?2)"),params![source,anchor],|r|r.get(0)).map_err(sql)?;
        if has_occurrences {
            return Ok(false);
        }
        if query.filters.since.is_some()
            || query.filters.until.is_some()
            || !query.facets.is_default()
        {
            return Ok(false);
        }
        if query.session_id.as_ref().is_some_and(|s| s.as_str() != id) {
            return Ok(false);
        }
        let provider: String = self
            .transaction
            .query_row(
                "SELECT provider_id FROM source_bindings WHERE source_id=?1",
                [source],
                |r| r.get(0),
            )
            .map_err(sql)?;
        if !query.filters.providers.is_empty()
            && !query
                .filters
                .providers
                .iter()
                .any(|p| p.as_str() == provider)
        {
            return Ok(false);
        }
        if let Some(repo) = &query.filters.repo {
            return Ok(matches!(data,EntityData::Session(s) if s.repo_slug.as_ref()==Some(repo)));
        }
        Ok(matches!(
            data,
            EntityData::Session(_)
                | EntityData::Document(_)
                | EntityData::Resume(_)
                | EntityData::Repository(_)
        ))
    }
}

fn graph_not_found() -> PortError {
    PortError::NotFound("managed context not found".into())
}
fn graph_too_large() -> PortError {
    PortError::WriterBusy(
        "managed graph exceeds bounded read capacity; restrict the request".into(),
    )
}
fn charge_graph(remaining: &mut usize, bytes: i64) -> PortResult<()> {
    let cost = usize::try_from(bytes)
        .map_err(|_| corrupt())?
        .checked_mul(4)
        .and_then(|n| n.checked_add(1024))
        .ok_or_else(graph_too_large)?;
    *remaining = remaining.checked_sub(cost).ok_or_else(graph_too_large)?;
    Ok(())
}

impl ManagedRead<'_> {
    /// Split one already-generated safe FTS expression into its phrases and
    /// score each with caller-supplied document-frequency work.
    ///
    /// The unicode61 tokenizer keeps some Rust-alphanumeric characters out of
    /// tokens (circled letters, for example), so a quoted phrase can contain
    /// zero tokens. FTS5 drops such a phrase from the implicit AND — verified
    /// against the bundled engine — while `managed_fts_stats` then reports one
    /// fewer phrase than this clause list. Counting the empty phrase would make
    /// every ordinary query look like catalog corruption, so a phrase with no
    /// tokens is skipped here exactly as FTS5 skips it at match time. The
    /// emptiness decision uses a real fts5vocab probe, not a Rust `char`
    /// approximation, so the two engines cannot drift.
    fn scoped_phrase_counts(
        &self,
        expression: &str,
        mut count: impl FnMut(&str, &dyn Fn() -> PortResult<()>) -> PortResult<f64>,
    ) -> PortResult<Vec<f64>> {
        let mut dfs = Vec::new();
        for phrase in fts_clauses(expression)? {
            if self.phrase_tokens(phrase) == 0 {
                continue;
            }
            dfs.push(count(phrase, &|| self.check_deadline())?);
        }
        Ok(dfs)
    }

    fn phrase_tokens(&self, phrase: &str) -> usize {
        let inner = phrase
            .strip_prefix('"')
            .map(|value| value.strip_suffix('*').unwrap_or(value))
            .unwrap_or(phrase)
            .strip_suffix('"')
            .unwrap_or(phrase)
            .replace("\"\"", "\"");
        TOKEN_PROBE
            .with(|probe| probe.borrow_mut().tokens(&inner))
            .unwrap_or(usize::MAX)
    }
}

thread_local! {
    /// One private probe table per reading thread. Managed reads own a live
    /// transaction, so the probe lives on a separate connection and only ever
    /// holds synthetic phrase text supplied by this module's own grammar.
    static TOKEN_PROBE: std::cell::RefCell<TokenProbe> =
        std::cell::RefCell::new(TokenProbe::default());
}

#[derive(Default)]
struct TokenProbe {
    conn: Option<rusqlite::Connection>,
}

impl TokenProbe {
    fn tokens(&mut self, text: &str) -> PortResult<usize> {
        let conn = match &self.conn {
            Some(conn) => conn,
            None => {
                let conn = rusqlite::Connection::open_in_memory().map_err(|_| corrupt())?;
                conn.execute_batch(
                    "CREATE VIRTUAL TABLE temp.token_probe USING fts5(x, tokenize='unicode61');
                     CREATE VIRTUAL TABLE temp.token_probe_vocab USING fts5vocab(temp, token_probe, 'instance');",
                )
                .map_err(|error| {
                    PortError::Backend(format!("token probe setup failed: {error}"))
                })?;
                self.conn.insert(conn)
            }
        };
        conn.execute("DELETE FROM temp.token_probe", [])
            .map_err(|_| corrupt())?;
        conn.execute(
            "INSERT INTO temp.token_probe(rowid, x) VALUES(1, ?1)",
            [text],
        )
        .map_err(|_| corrupt())?;
        let tokens: i64 = conn
            .query_row("SELECT COUNT(*) FROM temp.token_probe_vocab", [], |row| {
                row.get(0)
            })
            .map_err(|_| corrupt())?;
        usize::try_from(tokens).map_err(|_| corrupt())
    }
}

// Parse only the already-generated safe FTS grammar, not source/query tokens.
// Quoted punctuation/path phrases stay intact; escaped quotes and prefix * stay.
fn fts_clauses(expression: &str) -> PortResult<Vec<&str>> {
    let bytes = expression.as_bytes();
    let mut at = 0;
    let mut clauses = Vec::new();
    while at < bytes.len() {
        while at < bytes.len() && bytes[at] == b' ' {
            at += 1;
        }
        if at == bytes.len() {
            break;
        }
        let start = at;
        if bytes[at] != b'"' {
            return Err(corrupt());
        }
        at += 1;
        loop {
            if at >= bytes.len() {
                return Err(corrupt());
            }
            if bytes[at] == b'"' {
                at += 1;
                if at < bytes.len() && bytes[at] == b'"' {
                    at += 1;
                    continue;
                }
                break;
            }
            at += 1;
        }
        if at < bytes.len() && bytes[at] == b'*' {
            at += 1;
        }
        clauses.push(&expression[start..at]);
    }
    Ok(clauses)
}

#[cfg(test)]
mod token_probe_tests {
    use super::*;

    #[test]
    fn phrase_token_probe_matches_fts5_unicode61() {
        let mut probe = TokenProbe::default();
        assert_eq!(
            probe
                .tokens("hello")
                .map_err(|error| error.to_string())
                .unwrap(),
            1
        );
        assert_eq!(probe.tokens("\u{24b6}").unwrap(), 0);
        assert_eq!(probe.tokens("a\u{24b6}b").unwrap(), 2);
        assert_eq!(probe.tokens("mcp.json").unwrap(), 2);
        assert_eq!(probe.tokens("配置备份").unwrap(), 1);
    }
}

#[cfg(test)]
mod latest_proof_tests {
    use super::*;
    use control::*;
    use std::time::Duration;

    fn setup(conn: &Connection) {
        conn.execute_batch("PRAGMA foreign_keys=ON; CREATE TABLE store_metadata(singleton INTEGER PRIMARY KEY,active_generation INTEGER NOT NULL,projection_contract_version INTEGER NOT NULL DEFAULT 0,managed_mode INTEGER NOT NULL DEFAULT 0,destructive_epoch INTEGER NOT NULL DEFAULT 0); INSERT INTO store_metadata VALUES(1,0,0,0,0); BEGIN IMMEDIATE;").unwrap();
        create_schema(conn).unwrap();
        initialize_catalog_in_tx(conn, "synthetic-install", "synthetic-incarnation", 1).unwrap();
        conn.execute_batch("COMMIT").unwrap();
    }
    fn locator() -> &'static str {
        #[cfg(windows)]
        {
            r"C:\synthetic"
        }
        #[cfg(not(windows))]
        {
            "/synthetic"
        }
    }
    fn policy() -> ReadPolicy {
        ReadPolicy {
            installation_id: ControlId::parse("synthetic-install").unwrap(),
            policy_epoch: PolicyEpoch::new(1).unwrap(),
            control_seq: ControlSeq::new(100).unwrap(),
            selections: vec![Selection {
                id: ControlId::parse("selection").unwrap(),
                region: ScopeRegion {
                    provider: agent_session_grep_ports::SearchProvider::Claude,
                    locator: CanonicalLocator::parse(locator()).unwrap(),
                    kind: RootKind::Root,
                },
                root_identity: Some(ControlId::parse("root").unwrap()),
                enabled: true,
                revision: ControlSeq::new(1).unwrap(),
                created_at_ms: 0,
                revoked_at_ms: None,
            }],
            exclusions: vec![],
            request_intersection: RequestIntersection::Selected,
            maintenance: MaintenanceFence::idle(),
            revocations: vec![],
        }
    }
    fn barrier() -> LatestBarrier {
        LatestBarrier {
            id: ControlId::parse("barrier").unwrap(),
            policy_epoch: PolicyEpoch::new(1).unwrap(),
            admission_control_seq: ControlSeq::new(10).unwrap(),
            required_cycle_seq: CycleSeq::new(2).unwrap(),
            state: BarrierState::AwaitingCatalog,
            requested_wait_ms: 0,
            admitted_at_ms: 0,
            completed_cycle_seq: Some(CycleSeq::new(2).unwrap()),
            error: None,
            selections: vec![SelectionRevision {
                selection_id: ControlId::parse("selection").unwrap(),
                revision: ControlSeq::new(1).unwrap(),
                root_identity: ControlId::parse("root").unwrap(),
            }],
        }
    }
    fn source_observation(name: &str, cycle: i64, complete: bool) -> SourceObservation {
        SourceObservation {
            binding: SourceBinding {
                source_id: SourceId::parse(name).unwrap(),
                source_path: std::path::Path::new(locator())
                    .join(name)
                    .to_str()
                    .unwrap()
                    .into(),
                provider: agent_session_grep_ports::SearchProvider::Claude,
                namespace_id: None,
                root_identity: "root".into(),
            },
            revision_id: RevisionId::parse(&format!("revision-{name}-{cycle}")).unwrap(),
            revision_digest: format!("digest-{cycle}"),
            parser_version: 1,
            state: if complete {
                ObservationState::Complete
            } else {
                ObservationState::Incomplete
            },
            cycle_seq: cycle,
            worker_boot_id: "boot".into(),
            catalog_incarnation: "synthetic-incarnation".into(),
            policy_epoch: 1,
            started_control_seq: 10 + cycle,
            observed_at_ms: 0,
            committed_at_ms: 0,
            selections: vec![SelectionProof {
                selection_id: "selection".into(),
                selection_revision: 1,
                root_identity: "root".into(),
            }],
            repositories: vec![],
        }
    }
    fn publish_source(conn: &Connection, o: &SourceObservation) -> DiscoverySource {
        let batch = SourceBatch {
            source_path: o.binding.source_path.clone(),
            entries: vec![],
            placements: vec![],
            edges: vec![],
            activities: vec![],
            usage_events: vec![],
            relation_complete: true,
            len_bytes: Some(0),
            fingerprint: Some(o.revision_digest.clone()),
            provider_id: Some("claude-code".into()),
            resume_claims: vec![],
        };
        conn.execute_batch("BEGIN IMMEDIATE").unwrap();
        let mut publication = publish_source_in_tx(conn, &batch, o, 0).unwrap();
        finalize_publications_in_tx(conn, std::slice::from_mut(&mut publication)).unwrap();
        conn.execute_batch("COMMIT").unwrap();
        DiscoverySource {
            source_id: o.binding.source_id.clone(),
            revision_id: o.revision_id.clone(),
        }
    }
    fn discovery(cycle: i64, sources: Vec<DiscoverySource>) -> DiscoveryObservation {
        DiscoveryObservation {
            cycle_seq: cycle,
            worker_boot_id: "boot".into(),
            catalog_incarnation: "synthetic-incarnation".into(),
            policy_epoch: 1,
            started_control_seq: 10 + cycle,
            selection: SelectionProof {
                selection_id: "selection".into(),
                selection_revision: 1,
                root_identity: "root".into(),
            },
            sources,
            complete: true,
        }
    }
    fn publish(conn: &Connection, observation: &DiscoveryObservation) {
        try_publish(conn, observation).unwrap();
    }
    fn try_publish(conn: &Connection, observation: &DiscoveryObservation) -> PortResult<()> {
        conn.execute_batch("BEGIN IMMEDIATE").unwrap();
        let result = crate::managed_discovery::publish_in_tx(conn, observation);
        conn.execute_batch(if result.is_ok() { "COMMIT" } else { "ROLLBACK" })
            .unwrap();
        result
    }
    fn begin(conn: &Connection, cycle: i64) -> DiscoveryObservation {
        let mut observation = discovery(cycle, Vec::new());
        observation.complete = false;
        publish(conn, &observation);
        observation
    }
    fn read<'a>(conn: &'a Connection, policy: &ReadPolicy) -> ManagedRead<'a> {
        ManagedRead::begin_authorized(
            conn,
            policy,
            "synthetic-incarnation",
            Instant::now() + Duration::from_secs(5),
        )
        .unwrap()
    }
    fn satisfied(conn: &Connection) -> bool {
        read(conn, &policy()).latest_satisfied(&barrier()).unwrap()
    }

    #[test]
    fn scheduling_labels_and_clock_never_replace_same_snapshot_discovery_proof() {
        let conn = Connection::open_in_memory().unwrap();
        setup(&conn);
        assert!(!satisfied(&conn));
        let source = publish_source(&conn, &source_observation("a", 2, true));
        assert!(!satisfied(&conn));
        publish(&conn, &discovery(2, vec![source]));
        assert!(satisfied(&conn));
        let mut aborted = barrier();
        aborted.state = BarrierState::Blocked;
        aborted.error = Some(BackgroundFailure::WorkerRestarted);
        aborted.completed_cycle_seq = None;
        aborted.admitted_at_ms = i64::MAX;
        assert!(read(&conn, &policy()).latest_satisfied(&aborted).unwrap());
        let explicit = ManagedRead::begin(
            &conn,
            &ReadScope {
                catalog_incarnation: "synthetic-incarnation".into(),
                policy_epoch: 1,
                allowed: vec![],
            },
            Instant::now() + Duration::from_secs(5),
        )
        .unwrap();
        assert!(!explicit.latest_satisfied(&barrier()).unwrap());
    }

    #[test]
    fn empty_complete_set_is_valid_but_every_current_selection_is_required() {
        let conn = Connection::open_in_memory().unwrap();
        setup(&conn);
        publish(&conn, &discovery(2, vec![]));
        assert!(satisfied(&conn));
        let mut p = policy();
        let mut b = barrier();
        let mut other = p.selections[0].clone();
        other.id = ControlId::parse("second-selection").unwrap();
        p.selections.push(other);
        let mut selected = b.selections[0].clone();
        selected.selection_id = ControlId::parse("second-selection").unwrap();
        b.selections.push(selected);
        assert!(!read(&conn, &p).latest_satisfied(&b).unwrap());
        let mut second = discovery(2, vec![]);
        second.selection.selection_id = "second-selection".into();
        publish(&conn, &second);
        assert!(read(&conn, &p).latest_satisfied(&b).unwrap());
        for change in 0..4 {
            let mut p = p.clone();
            match change {
                0 => p.policy_epoch = PolicyEpoch::new(2).unwrap(),
                1 => p.selections[0].revision = ControlSeq::new(2).unwrap(),
                2 => p.selections[0].root_identity = Some(ControlId::parse("other-root").unwrap()),
                _ => p.selections[0].enabled = false,
            }
            assert!(!read(&conn, &p).latest_satisfied(&b).unwrap());
        }
    }

    #[test]
    fn newer_source_receipt_partial_or_new_source_needs_later_complete_discovery() {
        for new_source in [false, true] {
            let conn = Connection::open_in_memory().unwrap();
            setup(&conn);
            let first = publish_source(&conn, &source_observation("a", 2, true));
            publish(&conn, &discovery(2, vec![first]));
            assert!(satisfied(&conn));
            publish_source(
                &conn,
                &source_observation(if new_source { "b" } else { "a" }, 3, false),
            );
            assert!(!satisfied(&conn));
            let a = publish_source(&conn, &source_observation("a", 4, true));
            let mut sources = vec![a];
            if new_source {
                sources.push(publish_source(&conn, &source_observation("b", 4, true)));
            }
            assert!(!satisfied(&conn));
            publish(&conn, &discovery(4, sources));
            assert!(satisfied(&conn));
        }
        let conn = Connection::open_in_memory().unwrap();
        setup(&conn);
        publish(&conn, &discovery(2, vec![]));
        assert!(satisfied(&conn));
        publish_source(&conn, &source_observation("new", 3, true));
        assert!(!satisfied(&conn));
    }

    #[test]
    fn proof_and_source_heads_remain_pinned_across_wal_writes() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("catalog.db");
        let writer = Connection::open(&path).unwrap();
        writer.execute_batch("PRAGMA journal_mode=WAL").unwrap();
        setup(&writer);
        let reader = Connection::open(&path).unwrap();
        let pinned = read(&reader, &policy());
        let source = publish_source(&writer, &source_observation("a", 2, true));
        publish(&writer, &discovery(2, vec![source]));
        assert!(!pinned.latest_satisfied(&barrier()).unwrap());
        drop(pinned);
        let pinned = read(&reader, &policy());
        assert!(pinned.latest_satisfied(&barrier()).unwrap());
        let source = publish_source(&writer, &source_observation("a", 3, true));
        assert!(pinned.latest_satisfied(&barrier()).unwrap());
        drop(pinned);
        assert!(!satisfied(&reader));
        publish(&writer, &discovery(3, vec![source]));
        assert!(satisfied(&reader));
    }

    #[test]
    fn source_list_mutations_corrupt_the_shared_digest_and_errors_are_redacted() {
        for mutation in [
            "DELETE FROM discovery_sources WHERE source_id='a'",
            "UPDATE discovery_sources SET source_id='other' WHERE source_id='a'",
            "UPDATE discovery_sources SET revision_id='revision-b-2' WHERE source_id='a'",
            "UPDATE discovery_receipts SET source_set_digest='private-path-diagnostic'",
            "UPDATE discovery_receipts SET committed_generation=-1",
            "UPDATE discovery_receipts SET cycle_seq=-1",
            "UPDATE source_revision_receipts SET cycle_seq=-1 WHERE source_id='a'",
        ] {
            let conn = Connection::open_in_memory().unwrap();
            setup(&conn);
            let a = publish_source(&conn, &source_observation("a", 2, true));
            let b = publish_source(&conn, &source_observation("b", 2, true));
            publish(&conn, &discovery(2, vec![a, b]));
            conn.execute_batch("PRAGMA foreign_keys=OFF").unwrap();
            conn.execute_batch(mutation).unwrap();
            let error = read(&conn, &policy())
                .latest_satisfied(&barrier())
                .unwrap_err();
            assert!(matches!(error, PortError::SchemaIncompatible(_)));
            assert!(!error.to_string().contains("private-path-diagnostic"));
        }
    }

    #[test]
    fn missing_proof_and_well_formed_mismatched_tokens_are_unsatisfied() {
        for mutation in [
            "UPDATE discovery_receipts SET complete=0",
            "UPDATE discovery_receipts SET policy_epoch=2",
            "UPDATE discovery_receipts SET root_identity='other-root'",
            "UPDATE discovery_receipts SET selection_revision=2",
            "UPDATE discovery_receipts SET catalog_incarnation='restored-incarnation'",
            "UPDATE discovery_receipts SET started_control_seq=10",
            "UPDATE source_revision_receipts SET worker_boot_id='other-boot'",
            "UPDATE source_revision_receipts SET cycle_seq=3",
            "UPDATE source_revision_receipts SET started_control_seq=13",
            "UPDATE source_revision_receipts SET catalog_incarnation='other-incarnation'",
            "UPDATE receipt_selection_claims SET selection_revision=2",
            "DELETE FROM receipt_selection_claims",
            "UPDATE source_heads SET latest_receipt_id=NULL",
            "UPDATE source_heads SET last_attempt_id=NULL",
            "DELETE FROM source_scope_claims",
            "DELETE FROM source_revision_receipts",
        ] {
            let conn = Connection::open_in_memory().unwrap();
            setup(&conn);
            let a = publish_source(&conn, &source_observation("a", 2, true));
            publish(&conn, &discovery(2, vec![a]));
            conn.execute_batch("PRAGMA foreign_keys=OFF").unwrap();
            conn.execute_batch(mutation).unwrap();
            assert!(!satisfied(&conn), "{mutation}");
        }
    }

    #[test]
    fn later_incomplete_discovery_cannot_reuse_older_complete_observation() {
        let conn = Connection::open_in_memory().unwrap();
        setup(&conn);
        publish(&conn, &discovery(2, vec![]));
        begin(&conn, 3);
        assert!(!satisfied(&conn));
        let mut later = barrier();
        later.required_cycle_seq = CycleSeq::new(4).unwrap();
        assert!(!read(&conn, &policy()).latest_satisfied(&later).unwrap());
        publish(&conn, &discovery(4, vec![]));
        assert!(read(&conn, &policy()).latest_satisfied(&later).unwrap());
    }

    #[test]
    fn incomplete_discovery_blocks_old_empty_proof_before_any_source_binding_exists() {
        let conn = Connection::open_in_memory().unwrap();
        setup(&conn);
        publish(&conn, &discovery(2, vec![]));
        assert!(satisfied(&conn));
        let attempt = begin(&conn, 3);
        publish(&conn, &attempt); // Retrying begin does not erase or complete it.
        assert!(!satisfied(&conn));
        for table in [
            "source_bindings",
            "source_revision_receipts",
            "discovery_sources",
        ] {
            let count: i64 = conn
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0))
                .unwrap();
            assert_eq!(count, 0);
        }
        let mut failed = barrier();
        failed.state = BarrierState::Blocked;
        failed.error = Some(BackgroundFailure::WorkerRestarted);
        assert!(!read(&conn, &policy()).latest_satisfied(&failed).unwrap());
        // Recovery needs a complete verified set, not merely a later source commit.
        let source = publish_source(&conn, &source_observation("new", 3, true));
        assert!(!satisfied(&conn));
        publish(&conn, &discovery(3, vec![source]));
        assert!(satisfied(&conn));
        assert_eq!(
            conn.query_row("SELECT active_generation FROM store_metadata", [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            0
        );
    }

    #[test]
    fn discovery_begin_completion_and_reopen_keep_same_snapshot_semantics() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("catalog.db");
        let writer = Connection::open(&path).unwrap();
        writer.execute_batch("PRAGMA journal_mode=WAL").unwrap();
        setup(&writer);
        publish(&writer, &discovery(2, vec![]));
        let reader = Connection::open(&path).unwrap();
        let before = read(&reader, &policy());
        assert!(before.latest_satisfied(&barrier()).unwrap());
        begin(&writer, 3);
        assert!(before.latest_satisfied(&barrier()).unwrap());
        drop(before);
        drop(writer); // A stopped/crashed writer leaves the durable attempt intact.
        let pending = read(&reader, &policy());
        assert!(!pending.latest_satisfied(&barrier()).unwrap());
        let writer = Connection::open(&path).unwrap();
        writer.execute_batch("PRAGMA foreign_keys=ON").unwrap();
        let source = publish_source(&writer, &source_observation("new", 3, true));
        publish(&writer, &discovery(3, vec![source]));
        assert!(!pending.latest_satisfied(&barrier()).unwrap());
        drop(pending);
        assert!(satisfied(&reader));
    }

    #[test]
    fn incomplete_transition_requires_same_token_and_finalized_discovery_is_immutable() {
        let conn = Connection::open_in_memory().unwrap();
        setup(&conn);
        begin(&conn, 2);
        for changed in 0..6 {
            let mut completion = discovery(2, vec![]);
            match changed {
                0 => completion.worker_boot_id = "other-boot".into(),
                1 => completion.policy_epoch = 2,
                2 => completion.started_control_seq = 13,
                3 => completion.catalog_incarnation = "other-incarnation".into(),
                4 => completion.selection.root_identity = "other-root".into(),
                _ => completion.selection.selection_revision = 2,
            }
            assert!(try_publish(&conn, &completion).is_err());
            assert!(!satisfied(&conn));
        }
        let completion = discovery(2, vec![]);
        publish(&conn, &completion);
        publish(&conn, &completion);
        assert!(satisfied(&conn));
        let mut downgrade = completion;
        downgrade.complete = false;
        assert!(try_publish(&conn, &downgrade).is_err());
        assert!(satisfied(&conn));
    }

    #[test]
    fn confirmed_absence_receipt_must_be_in_the_complete_covered_set() {
        for included in [false, true] {
            let conn = Connection::open_in_memory().unwrap();
            setup(&conn);
            begin(&conn, 2);
            let mut absent = source_observation("removed", 2, true);
            absent.revision_digest = "confirmed_absent".into();
            let receipt = publish_source(&conn, &absent);
            publish(
                &conn,
                &discovery(2, if included { vec![receipt] } else { vec![] }),
            );
            assert_eq!(satisfied(&conn), included);
        }
    }

    #[test]
    fn managed_store_begin_fences_unreadable_new_source_and_survives_worker_restart() {
        use crate::{
            SqliteControlStore,
            managed_locks::{ExclusiveGuard, LockKind},
            managed_store::ManagedStore,
        };
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("private");
        let catalog = root.join("catalog.db");
        let control = SqliteControlStore::create(
            &root,
            &ControlId::parse("synthetic-install").unwrap(),
            DesiredUpdates::Running,
        )
        .unwrap();
        // This isolated fixture has no competing writer. Keep its complete
        // expected-success setup under one explicit bound; parallel test load
        // must not make the production 250ms default look like real contention.
        let fixture_end = Instant::now() + Duration::from_secs(30);
        let current = || {
            control
                .with_runtime_deadline(fixture_end, || control.status())
                .unwrap()
                .policy
                .control_seq
        };
        let selected = control
            .with_runtime_deadline(fixture_end, || {
                control.add_selection(
                    current(),
                    SelectionRequest {
                        region: ScopeRegion {
                            provider: agent_session_grep_ports::SearchProvider::Claude,
                            locator: CanonicalLocator::from_path(temp.path()).unwrap(),
                            kind: RootKind::Root,
                        },
                        root_identity: Some(ControlId::parse("root").unwrap()),
                        now_ms: 1,
                    },
                )
            })
            .unwrap()
            .value;
        let selection = SelectionRevision {
            selection_id: selected.id,
            revision: selected.revision,
            root_identity: selected.root_identity.unwrap(),
        };
        let guard = ExclusiveGuard::try_acquire(&root, LockKind::Background).unwrap();
        let worker = control
            .with_runtime_deadline(fixture_end, || {
                control.bind_worker(&guard, ControlId::parse("first-boot").unwrap())
            })
            .unwrap();
        control
            .with_runtime_deadline(fixture_end, || {
                control.register_worker(current(), &worker, 1, 2)
            })
            .unwrap();
        let store = ManagedStore::create(
            &catalog,
            &control,
            ControlId::parse("synthetic-incarnation").unwrap(),
            2,
        )
        .unwrap();
        control
            .with_runtime_deadline(fixture_end, || store.reconcile_progress(&control, &worker))
            .unwrap();
        let LatestAdmission::Queued(barrier) = control
            .with_runtime_deadline(fixture_end, || {
                control.admit_latest(
                    current(),
                    LatestRequest {
                        selections: vec![selection.clone()],
                        max_wait_ms: 5000,
                        now_ms: 3,
                    },
                )
            })
            .unwrap()
            .value
        else {
            panic!("expected barrier")
        };
        let cycle = control
            .with_runtime_deadline(fixture_end, || {
                control.start_cycle(current(), &worker, barrier.required_cycle_seq, 4)
            })
            .unwrap()
            .value;
        control
            .with_runtime_deadline(fixture_end, || {
                store.begin_discovery(&control, &worker, &cycle, &selection, 4)
            })
            .unwrap();
        control
            .with_runtime_deadline(fixture_end, || {
                store.commit_discovery(&control, &worker, &cycle, &selection, &[], 5)
            })
            .unwrap();
        let latest = || {
            store
                .with_read(
                    &control,
                    RequestIntersection::Selected,
                    fixture_end,
                    |read| read.latest_satisfied(&barrier),
                )
                .unwrap()
        };
        assert!(latest());
        control
            .with_runtime_deadline(fixture_end, || {
                control.acknowledge_discovery(
                    current(),
                    &worker,
                    DiscoveryAcknowledgement {
                        token: cycle.token.clone(),
                        selection: selection.clone(),
                        complete: true,
                        discovered_count: 0,
                        observed_count: 0,
                        committed_count: 0,
                        error: None,
                    },
                )
            })
            .unwrap();
        control
            .with_runtime_deadline(fixture_end, || {
                control.finish_cycle(
                    current(),
                    &worker,
                    cycle.token.cycle_seq,
                    CycleFinish::Committed,
                    6,
                )
            })
            .unwrap();
        let CycleAdmission::Queued(queued) = control
            .with_runtime_deadline(fixture_end, || {
                control.queue_cycle(current(), vec![selection.clone()])
            })
            .unwrap()
            .value
        else {
            panic!("expected cycle")
        };
        let failed = control
            .with_runtime_deadline(fixture_end, || {
                control.start_cycle(current(), &worker, queued.token.cycle_seq, 7)
            })
            .unwrap()
            .value;
        // Before even attempting an unbound source, persist the incomplete set.
        control
            .with_runtime_deadline(fixture_end, || {
                store.begin_discovery(&control, &worker, &failed, &selection, 7)
            })
            .unwrap();
        control
            .with_runtime_deadline(fixture_end, || {
                store.begin_discovery(&control, &worker, &failed, &selection, 7)
            })
            .unwrap();
        assert!(!latest());
        control
            .with_runtime_deadline(fixture_end, || {
                control.acknowledge_source(
                    current(),
                    &worker,
                    SourceAcknowledgement {
                        source_id: ControlId::parse("new-unreadable-source").unwrap(),
                        provider: agent_session_grep_ports::SearchProvider::Claude,
                        token: failed.token.clone(),
                        selection: selection.clone(),
                        attempted_at_ms: 8,
                        coverage: Coverage::Partial,
                        update_state: UpdateState::Deferred,
                        backfill_state: BackfillState::Pending,
                        error: Some(BackgroundFailure::Failed),
                        receipt: None,
                        confirmation: None,
                    },
                )
            })
            .unwrap();
        control
            .with_runtime_deadline(fixture_end, || {
                control.acknowledge_discovery(
                    current(),
                    &worker,
                    DiscoveryAcknowledgement {
                        token: failed.token.clone(),
                        selection: selection.clone(),
                        complete: false,
                        discovered_count: 1,
                        observed_count: 0,
                        committed_count: 0,
                        error: Some(BackgroundFailure::Failed),
                    },
                )
            })
            .unwrap();
        control
            .with_runtime_deadline(fixture_end, || {
                control.finish_cycle(
                    current(),
                    &worker,
                    failed.token.cycle_seq,
                    CycleFinish::Partial,
                    9,
                )
            })
            .unwrap();
        assert!(
            control
                .with_runtime_deadline(fixture_end, || store.background_sources(&control))
                .unwrap()
                .is_empty()
        );
        assert!(!latest());
        drop(worker);
        drop(guard);
        let guard = ExclusiveGuard::try_acquire(&root, LockKind::Background).unwrap();
        let worker = control
            .with_runtime_deadline(fixture_end, || {
                control.bind_worker(&guard, ControlId::parse("second-boot").unwrap())
            })
            .unwrap();
        control
            .with_runtime_deadline(fixture_end, || {
                control.register_worker(current(), &worker, 2, 10)
            })
            .unwrap();
        control
            .with_runtime_deadline(fixture_end, || store.reconcile_progress(&control, &worker))
            .unwrap();
        assert!(!latest());
        assert!(
            store
                .begin_discovery(&control, &worker, &failed, &selection, 10)
                .is_err()
        );
        let CycleAdmission::Queued(queued) = control
            .with_runtime_deadline(fixture_end, || {
                control.queue_cycle(current(), vec![selection.clone()])
            })
            .unwrap()
            .value
        else {
            panic!("expected recovery cycle")
        };
        let recovered = control
            .with_runtime_deadline(fixture_end, || {
                control.start_cycle(current(), &worker, queued.token.cycle_seq, 11)
            })
            .unwrap()
            .value;
        assert!(recovered.token.cycle_seq > failed.token.cycle_seq);
        control
            .with_runtime_deadline(fixture_end, || {
                store.begin_discovery(&control, &worker, &recovered, &selection, 11)
            })
            .unwrap();
        assert!(!latest());
        control
            .with_runtime_deadline(fixture_end, || {
                store.commit_discovery(&control, &worker, &recovered, &selection, &[], 12)
            })
            .unwrap();
        assert!(latest());
        assert!(
            store
                .begin_discovery(&control, &worker, &recovered, &selection, 13)
                .is_err()
        );
        assert!(latest());
    }

    #[test]
    fn omitted_old_readable_evidence_and_expired_budget_cannot_report_latest() {
        let conn = Connection::open_in_memory().unwrap();
        setup(&conn);
        let o = source_observation("a", 1, true);
        let batch = SourceBatch {
            source_path: o.binding.source_path.clone(),
            entries: vec![(
                StableId::native_checked(IdKind::Session, "old-session").unwrap(),
                b"{}".to_vec(),
                String::new(),
            )],
            placements: vec![],
            edges: vec![],
            activities: vec![],
            usage_events: vec![],
            relation_complete: true,
            len_bytes: Some(0),
            fingerprint: Some(o.revision_digest.clone()),
            provider_id: Some("claude-code".into()),
            resume_claims: vec![],
        };
        conn.execute_batch("BEGIN IMMEDIATE").unwrap();
        let mut result = publish_source_in_tx(&conn, &batch, &o, 1).unwrap();
        conn.execute("UPDATE store_metadata SET active_generation=1", [])
            .unwrap();
        finalize_publications_in_tx(&conn, std::slice::from_mut(&mut result)).unwrap();
        conn.execute_batch("COMMIT").unwrap();
        publish(&conn, &discovery(2, vec![]));
        assert!(!satisfied(&conn));
        let mut read = read(&conn, &policy());
        read.deadline = Instant::now();
        assert!(matches!(
            read.latest_satisfied(&barrier()),
            Err(PortError::WriterBusy(_))
        ));
    }

    fn overlap_locators() -> (&'static str, &'static str) {
        #[cfg(windows)]
        {
            (r"C:\synthetic", r"C:\synthetic\child")
        }
        #[cfg(not(windows))]
        {
            ("/synthetic", "/synthetic/child")
        }
    }
    fn overlap_policy() -> ReadPolicy {
        let mut policy = policy();
        let (_, child) = overlap_locators();
        let mut second = policy.selections[0].clone();
        second.id = ControlId::parse("second-selection").unwrap();
        second.region.locator = CanonicalLocator::parse(child).unwrap();
        second.root_identity = Some(ControlId::parse("child-root").unwrap());
        policy.selections.push(second);
        policy
    }
    fn overlap_barrier(selections: &[&str]) -> LatestBarrier {
        let mut barrier = barrier();
        barrier.selections.clear();
        for (id, root) in [("selection", "root"), ("second-selection", "child-root")] {
            if selections.contains(&id) {
                barrier.selections.push(SelectionRevision {
                    selection_id: ControlId::parse(id).unwrap(),
                    revision: ControlSeq::new(1).unwrap(),
                    root_identity: ControlId::parse(root).unwrap(),
                });
            }
        }
        barrier
    }
    fn overlap_source(cycle: i64, claims: &[(&str, &str)]) -> SourceObservation {
        let (_, child) = overlap_locators();
        let mut observation = source_observation("a", cycle, true);
        observation.binding.source_path = format!("{child}{}a.jsonl", std::path::MAIN_SEPARATOR);
        observation.selections.clear();
        for (selection, root) in claims {
            observation.selections.push(SelectionProof {
                selection_id: (*selection).into(),
                selection_revision: 1,
                root_identity: (*root).into(),
            });
        }
        observation
    }
    fn overlap_discovery(
        cycle: i64,
        selection: &str,
        root: &str,
        sources: Vec<DiscoverySource>,
    ) -> DiscoveryObservation {
        let mut observation = discovery(cycle, sources);
        observation.selection.selection_id = selection.into();
        observation.selection.root_identity = root.into();
        observation
    }
    fn publish_overlap(conn: &Connection) -> DiscoverySource {
        let source = publish_source(
            conn,
            &overlap_source(
                2,
                &[("selection", "root"), ("second-selection", "child-root")],
            ),
        );
        publish(
            conn,
            &overlap_discovery(2, "selection", "root", vec![source.clone()]),
        );
        publish(
            conn,
            &overlap_discovery(2, "second-selection", "child-root", vec![source.clone()]),
        );
        source
    }

    #[test]
    fn overlapping_roots_publish_one_source_and_satisfy_each_selection() {
        let conn = Connection::open_in_memory().unwrap();
        setup(&conn);
        publish_overlap(&conn);
        let policy = overlap_policy();
        let read = read(&conn, &policy);
        // The historical binding root differs from the child claim; ordinary
        // evidence and both latest proofs still work independently.
        assert_eq!(read.source_progress().unwrap().len(), 1);
        assert!(
            read.latest_satisfied(&overlap_barrier(&["selection", "second-selection"]))
                .unwrap()
        );
        assert!(
            read.latest_satisfied(&overlap_barrier(&["second-selection"]))
                .unwrap()
        );
        assert!(
            read.latest_satisfied(&overlap_barrier(&["selection"]))
                .unwrap()
        );
    }

    #[test]
    fn per_selection_claim_root_must_match_that_selections_discovery_root() {
        let conn = Connection::open_in_memory().unwrap();
        setup(&conn);
        publish_overlap(&conn);
        conn.execute_batch(
            "UPDATE receipt_selection_claims SET root_identity='other-root' WHERE selection_id='second-selection'",
        )
        .unwrap();
        let policy = overlap_policy();
        let read = read(&conn, &policy);
        assert!(
            !read
                .latest_satisfied(&overlap_barrier(&["selection", "second-selection"]))
                .unwrap()
        );
        assert!(
            read.latest_satisfied(&overlap_barrier(&["selection"]))
                .unwrap()
        );
    }

    #[test]
    fn healthy_overlap_root_supplies_evidence_while_offline_root_blocks_latest() {
        let conn = Connection::open_in_memory().unwrap();
        setup(&conn);
        let source = publish_source(
            &conn,
            &overlap_source(2, &[("second-selection", "child-root")]),
        );
        publish(&conn, &overlap_discovery(2, "selection", "root", vec![]));
        publish(
            &conn,
            &overlap_discovery(2, "second-selection", "child-root", vec![source]),
        );
        let policy = overlap_policy();
        let read = read(&conn, &policy);
        // Ordinary evidence survives through the healthy child claim.
        assert_eq!(read.source_progress().unwrap().len(), 1);
        // The incomplete parent cannot borrow the child's completion.
        assert!(
            !read
                .latest_satisfied(&overlap_barrier(&["selection"]))
                .unwrap()
        );
        assert!(
            !read
                .latest_satisfied(&overlap_barrier(&["selection", "second-selection"]))
                .unwrap()
        );
        assert!(
            read.latest_satisfied(&overlap_barrier(&["second-selection"]))
                .unwrap()
        );
    }

    #[test]
    fn parent_root_exclusion_denies_shared_source_despite_child_claim() {
        let conn = Connection::open_in_memory().unwrap();
        setup(&conn);
        publish_overlap(&conn);
        let mut policy = overlap_policy();
        let (parent, _) = overlap_locators();
        policy.exclusions.push(Exclusion {
            id: ControlId::parse("deny-parent").unwrap(),
            region: ExcludedRegion::Locator(ScopeRegion {
                provider: agent_session_grep_ports::SearchProvider::Claude,
                locator: CanonicalLocator::parse(parent).unwrap(),
                kind: RootKind::Root,
            }),
            revision: ControlSeq::new(1).unwrap(),
            created_policy_epoch: PolicyEpoch::new(1).unwrap(),
            created_at_ms: 1,
        });
        let read = read(&conn, &policy);
        assert!(read.source_progress().unwrap().is_empty());
    }
}
