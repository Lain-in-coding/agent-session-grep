//! Checked private source receipts shared by disclosure and publication.
//!
//! This decoder checks persisted structure and source ownership. Historical
//! incarnations remain structurally valid; callers separately prove authorized
//! retained origin, current snapshot generation, policy, cycle and discovery.
//! No database/source mutation, implicit transaction, clock or permission grant.

use agent_session_grep_ports::{
    PortError, PortResult,
    control::ControlId,
    managed::{RevisionId, RevisionRef, SourceId},
};
use rusqlite::{Connection, OptionalExtension, Row};

fn corrupt() -> PortError {
    PortError::SchemaIncompatible("managed source receipt is invalid".into())
}
fn invalid() -> PortError {
    PortError::InvalidRequest("invalid managed source receipt reference".into())
}
fn sql(error: rusqlite::Error) -> PortError {
    match error.sqlite_error_code() {
        Some(rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked) => {
            PortError::WriterBusy("managed source receipt storage is busy".into())
        }
        Some(rusqlite::ErrorCode::OperationInterrupted) => {
            PortError::WriterBusy("managed source receipt deadline exceeded".into())
        }
        _ => corrupt(),
    }
}

struct StoredReceipt {
    revision: String,
    source: String,
    sequence: i64,
    digest: String,
    parser: i64,
    completeness: String,
    published: i64,
    cycle: i64,
    boot: String,
    incarnation: String,
    policy: i64,
    started: i64,
    content_revision: Option<String>,
    content_digest: Option<String>,
    generation: Option<i64>,
    observed: i64,
    committed: Option<i64>,
    reason: Option<String>,
    binding_source: Option<String>,
}

impl StoredReceipt {
    fn decode(row: &Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            revision: row.get(0)?,
            source: row.get(1)?,
            sequence: row.get(2)?,
            digest: row.get(3)?,
            parser: row.get(4)?,
            completeness: row.get(5)?,
            published: row.get(6)?,
            cycle: row.get(7)?,
            boot: row.get(8)?,
            incarnation: row.get(9)?,
            policy: row.get(10)?,
            started: row.get(11)?,
            content_revision: row.get(12)?,
            content_digest: row.get(13)?,
            generation: row.get(14)?,
            observed: row.get(15)?,
            committed: row.get(16)?,
            reason: row.get(17)?,
            binding_source: row.get(18)?,
        })
    }

    fn checked(self) -> PortResult<CheckedReceipt> {
        let revision = RevisionId::parse(&self.revision).map_err(|_| corrupt())?;
        let source = SourceId::parse(&self.source).map_err(|_| corrupt())?;
        if self.binding_source.as_deref() != Some(self.source.as_str())
            || self.sequence < 1
            || self.parser < 1
            || self.parser > i64::from(u32::MAX)
            || self.cycle < 1
            || self.policy < 0
            || self.started < 1
            || self.observed < 0
            || self.generation.is_some_and(|value| value < 0)
            || self.committed.is_some_and(|value| value < 0)
            || self.digest.is_empty()
            || self.digest.len() > 256
            || self.digest.chars().any(char::is_control)
        {
            return Err(corrupt());
        }
        ControlId::parse(&self.boot).map_err(|_| corrupt())?;
        ControlId::parse(&self.incarnation).map_err(|_| corrupt())?;
        let published = match self.published {
            0 => false,
            1 => true,
            _ => return Err(corrupt()),
        };
        let content_revision = self
            .content_revision
            .as_deref()
            .map(|value| RevisionId::parse(value).map_err(|_| corrupt()))
            .transpose()?;
        if let Some(digest) = &self.content_digest
            && (digest.len() != 64
                || !digest
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)))
        {
            return Err(corrupt());
        }
        if published {
            if !matches!(self.completeness.as_str(), "complete" | "append")
                || self.generation.is_none()
                || self.committed.is_none()
                || content_revision.is_none()
                || self.content_digest.is_none()
                || self.reason.is_some()
            {
                return Err(corrupt());
            }
        } else if self.completeness != "partial"
            || self.generation.is_some()
            || self.committed.is_some()
            || self.content_digest.is_some()
            || !matches!(
                self.reason.as_deref(),
                Some("incomplete" | "unstable" | "rewrite_pending" | "deletion_pending")
            )
        {
            return Err(corrupt());
        }
        // Wall-clock times are display-only. A backwards clock between observe
        // and commit must not fabricate corruption or monotonic freshness.
        Ok(CheckedReceipt {
            source,
            sequence: self.sequence,
            content_revision,
            content_digest: self.content_digest,
            reference: RevisionRef {
                revision_id: revision,
                digest: self.digest,
                observed_at_ms: self.observed,
                cycle_seq: self.cycle,
                worker_boot_id: self.boot,
                catalog_incarnation: self.incarnation,
                policy_epoch: self.policy,
                started_control_seq: self.started,
                committed_generation: self.generation,
                published,
            },
        })
    }
}

struct CheckedReceipt {
    source: SourceId,
    sequence: i64,
    content_revision: Option<RevisionId>,
    content_digest: Option<String>,
    reference: RevisionRef,
}

fn stored(conn: &Connection, revision: &str) -> PortResult<CheckedReceipt> {
    conn.query_row(
        "SELECT r.revision_id,r.source_id,r.revision_seq,r.revision_digest,r.parser_version,r.completeness,r.published,r.cycle_seq,r.worker_boot_id,r.catalog_incarnation,r.policy_epoch,r.started_control_seq,r.content_revision_id,r.content_set_digest,r.committed_generation,r.observed_at_ms,r.committed_at_ms,r.reason,b.source_id FROM source_revision_receipts r LEFT JOIN source_bindings b ON b.source_id=r.source_id WHERE r.revision_id=?1",
        [revision], StoredReceipt::decode,
    ).optional().map_err(sql)?.ok_or_else(corrupt)?.checked()
}

/// Decode one receipt and, if retained, its actual content-producing receipt.
/// At most two bounded metadata rows are inspected; no recursive lineage walk.
/// An expected source is mandatory when following a source-head pointer, since
/// a syntactically valid receipt owned by another source is not that head's proof.
/// Historical incarnation validity here grants neither retained-origin access
/// nor current observation coverage; the receiving caller must prove those.
pub(crate) fn read_checked(
    conn: &Connection,
    revision: &str,
    expected_source: Option<&str>,
) -> PortResult<RevisionRef> {
    let expected_revision = RevisionId::parse(revision).map_err(|_| invalid())?;
    let expected_source = expected_source
        .map(|value| SourceId::parse(value).map_err(|_| invalid()))
        .transpose()?;
    let receipt = stored(conn, revision)?;
    if receipt.reference.revision_id != expected_revision
        || expected_source
            .as_ref()
            .is_some_and(|source| *source != receipt.source)
    {
        return Err(corrupt());
    }
    if let Some(content_revision) = &receipt.content_revision {
        if content_revision == &receipt.reference.revision_id {
            if !receipt.reference.published {
                return Err(corrupt());
            }
        } else {
            let content = stored(conn, content_revision.as_str())?;
            if content.source != receipt.source
                || !content.reference.published
                || content.sequence >= receipt.sequence
                || content.content_revision.as_ref() != Some(&content.reference.revision_id)
                || (receipt.reference.published
                    && (receipt.content_digest != content.content_digest
                        || content.reference.committed_generation
                            > receipt.reference.committed_generation))
            {
                return Err(corrupt());
            }
        }
    }
    Ok(receipt.reference)
}
