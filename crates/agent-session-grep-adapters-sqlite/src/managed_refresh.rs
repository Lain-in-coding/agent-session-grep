//! Receipt-only publication after a full verification in the managed facade.
//! No source proof, raw connection, or unverified publication API is public.
use crate::{managed, managed_receipt, managed_source_context};
use agent_session_grep_ports::{
    PortError, PortResult, SourceSnapshot,
    control::{CanonicalLocator, ControlId, ReadPolicy},
    managed::{ObservationState, Publication, RevisionRef, SourceBinding, SourceObservation},
};
use rusqlite::{Connection, OptionalExtension, params};
use std::{path::Path, time::Instant};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RefreshOutcome {
    Refreshed(Publication),
    Ineligible(RefreshIneligible),
}

/// Only these recognized misses permit full publication on the same input/end.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefreshIneligible {
    Provider,
    SourceKind,
    HeadNotCurrent,
    DigestOrLength,
    ParserVersion,
    Scan,
    SourceContext,
    RetainedEvidence,
    InstallationProof,
    Repositories,
    PriorRepositoryProjection,
}

fn invalid() -> PortError {
    PortError::InvalidRequest("invalid managed unchanged refresh".into())
}
fn corrupt() -> PortError {
    PortError::SchemaIncompatible("managed unchanged refresh evidence is invalid".into())
}
fn changed() -> PortError {
    PortError::GenerationMismatch("managed unchanged refresh input changed".into())
}
fn sql(error: rusqlite::Error) -> PortError {
    match error.sqlite_error_code() {
        Some(
            rusqlite::ErrorCode::DatabaseBusy
            | rusqlite::ErrorCode::DatabaseLocked
            | rusqlite::ErrorCode::OperationInterrupted,
        ) => PortError::WriterBusy("managed unchanged refresh is busy or expired".into()),
        _ => corrupt(),
    }
}
pub(crate) fn time(deadline: Instant) -> PortResult<()> {
    if Instant::now() >= deadline {
        Err(PortError::WriterBusy(
            "managed unchanged refresh deadline exceeded".into(),
        ))
    } else {
        Ok(())
    }
}
fn hash_shape(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
pub(crate) fn validate_input(
    observation: &SourceObservation,
    snapshot: &SourceSnapshot,
    sqlite_byte_limit: u64,
    deadline: Instant,
) -> PortResult<()> {
    time(deadline)?;
    if !matches!(
        sqlite_byte_limit,
        agent_session_grep_ports::SQLITE_MAX_SOURCE_BYTES | 268_435_456
    ) || observation.parser_version == 0
        || observation.state != ObservationState::Complete
        || observation.cycle_seq < 1
        || observation.started_control_seq < 1
        || observation.policy_epoch < 0
        || observation.observed_at_ms < 0
        || observation.committed_at_ms < 0
        || snapshot.mtime_ms < 0
        || snapshot.len > i64::MAX as u64
        || snapshot.len > agent_session_grep_ports::JSON_FAMILY_MAX_SOURCE_BYTES
        || snapshot.path != observation.binding.source_path
        || snapshot.fingerprint != observation.revision_digest
    {
        return Err(invalid());
    }
    CanonicalLocator::parse(&snapshot.path)?;
    for value in [
        &observation.binding.root_identity,
        &observation.worker_boot_id,
        &observation.catalog_incarnation,
    ] {
        ControlId::parse(value)?;
    }
    if let Some(namespace) = &observation.binding.namespace_id {
        ControlId::parse(namespace)?;
    }
    let fingerprint = snapshot
        .fingerprint
        .strip_prefix("sqlite:")
        .unwrap_or(&snapshot.fingerprint);
    if !hash_shape(fingerprint) {
        return Err(invalid());
    }
    let mut selections = std::collections::BTreeSet::new();
    for proof in &observation.selections {
        ControlId::parse(&proof.selection_id)?;
        ControlId::parse(&proof.root_identity)?;
        if proof.selection_revision < 0 || !selections.insert(&proof.selection_id) {
            return Err(invalid());
        }
    }
    if selections.is_empty() {
        return Err(invalid());
    }
    Ok(())
}

/// Check every path component before opening the admitted source. This is the
/// existing bounded snapshot race, not a provider lock or filesystem CAS.
pub(crate) fn verify_source_path(binding: &SourceBinding, deadline: Instant) -> PortResult<()> {
    let path = Path::new(&binding.source_path);
    for ancestor in path.ancestors() {
        time(deadline)?;
        let metadata = std::fs::symlink_metadata(ancestor)
            .map_err(|_| PortError::SourceIo("managed refresh source is unavailable".into()))?;
        if metadata.file_type().is_symlink() {
            return Err(invalid());
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            if metadata.file_attributes() & 0x400 != 0 {
                return Err(invalid());
            }
        }
        if ancestor == path && !metadata.is_file() {
            return Err(invalid());
        }
    }
    time(deadline)
}

struct Baseline {
    content_revision: String,
    content_digest: String,
    sequence: i64,
    generation: i64,
    epoch: i64,
}

struct ScanRow {
    length: i64,
    digest: Option<String>,
    provider: Option<String>,
    parser: Option<i64>,
}

/// Read-only preflight is repeated in the immediate transaction after hashing.
/// A stale expected receipt is always an error, even for an unsupported input.
pub(crate) fn check_baseline(
    conn: &Connection,
    expected: &RevisionRef,
    observation: &SourceObservation,
    snapshot: &SourceSnapshot,
    policy: &ReadPolicy,
    deadline: Instant,
) -> PortResult<Option<RefreshIneligible>> {
    baseline(conn, expected, observation, snapshot, policy, deadline).map(|(_, miss)| miss)
}

fn baseline(
    conn: &Connection,
    expected: &RevisionRef,
    observation: &SourceObservation,
    snapshot: &SourceSnapshot,
    policy: &ReadPolicy,
    deadline: Instant,
) -> PortResult<(Baseline, Option<RefreshIneligible>)> {
    time(deadline)?;
    let source = observation.binding.source_id.as_str();
    let stored = managed_receipt::read_checked(conn, expected.revision_id.as_str(), Some(source))?;
    if stored != *expected {
        return Err(changed());
    }
    managed_source_context::verify_observation_policy(conn, observation, policy)?;
    let (path, provider, namespace, root): (String, String, Option<String>, String) = conn
        .query_row(
            "SELECT source_path,provider_id,namespace_id,root_identity FROM source_bindings WHERE source_id=?1",
            [source],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .map_err(sql)?;
    if path != observation.binding.source_path
        || provider != observation.binding.provider.as_str()
        || namespace != observation.binding.namespace_id
        || root != observation.binding.root_identity
    {
        return Err(changed());
    }
    let (latest, attempt, visible, digest, state): (
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        String,
    ) = conn
        .query_row(
            "SELECT latest_receipt_id,last_attempt_id,visible_revision_id,content_set_digest,update_state FROM source_heads WHERE source_id=?1",
            [source],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        )
        .optional()
        .map_err(sql)?
        .ok_or_else(corrupt)?;
    if latest.as_deref() != Some(expected.revision_id.as_str()) {
        return Err(changed());
    }
    if !matches!(
        state.as_str(),
        "unknown" | "current" | "partial" | "failed" | "deferred" | "paused" | "revoked"
    ) {
        return Err(corrupt());
    }
    let duplicate: bool = conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM source_revision_receipts WHERE revision_id=?1)",
            [observation.revision_id.as_str()],
            |r| r.get(0),
        )
        .map_err(sql)?;
    if duplicate {
        return Err(changed());
    }
    let (incarnation, generation, epoch): (String, i64, i64) = conn
        .query_row(
            "SELECT catalog_incarnation,active_generation,destructive_epoch FROM catalog_meta CROSS JOIN store_metadata WHERE catalog_meta.singleton=1 AND store_metadata.singleton=1 AND managed_mode=1 AND projection_contract_version=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .map_err(sql)?;
    if incarnation != observation.catalog_incarnation || generation < 0 || epoch < 0 {
        return Err(corrupt());
    }
    let attempt = attempt.ok_or_else(corrupt)?;
    let attempted = managed_receipt::read_checked(conn, &attempt, Some(source))?;
    if attempted.published
        && attempted
            .committed_generation
            .is_none_or(|value| value > generation)
    {
        return Err(corrupt());
    }
    if matches!(provider.as_str(), "claude-code" | "codex") && !hash_shape(&expected.digest) {
        return Err(corrupt());
    }
    let mut miss = None;
    if !matches!(provider.as_str(), "claude-code" | "codex") {
        miss = Some(RefreshIneligible::Provider);
    }
    if snapshot.len == 0
        || snapshot.fingerprint.starts_with("sqlite:")
        || Path::new(&path).extension().and_then(|v| v.to_str()) != Some("jsonl")
    {
        miss.get_or_insert(RefreshIneligible::SourceKind);
    }
    let (parser, completeness, content, content_digest): (
        i64,
        String,
        Option<String>,
        Option<String>,
    ) = conn
        .query_row(
            "SELECT parser_version,completeness,content_revision_id,content_set_digest FROM source_revision_receipts WHERE revision_id=?1",
            [expected.revision_id.as_str()],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .map_err(sql)?;
    if Some(attempt.as_str()) != latest.as_deref()
        || state != "current"
        || !expected.published
        || completeness != "complete"
    {
        miss.get_or_insert(RefreshIneligible::HeadNotCurrent);
    }
    let (mut retained, empty_original_context) = validate_lineage(
        conn,
        &observation.binding,
        &incarnation,
        generation,
        deadline,
    )?;
    if expected.published {
        retained |= validate_original(conn, &stored, &incarnation, generation)?;
    }
    let empty_head_context = managed_source_context::verify_refresh_context_head(
        conn,
        &observation.binding,
        expected.revision_id.as_str(),
        deadline,
    )?;
    if !empty_original_context || !empty_head_context {
        miss.get_or_insert(RefreshIneligible::SourceContext);
    }
    if !plain_documents(conn, source, &provider, deadline)? {
        miss.get_or_insert(RefreshIneligible::SourceKind);
    }
    if !observation.repositories.is_empty() {
        miss.get_or_insert(RefreshIneligible::Repositories);
    }
    let repositories: bool = conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM source_entity_projections WHERE source_id=?1 AND kind='repo_identity')",
            [source],
            |r| r.get(0),
        )
        .map_err(sql)?;
    if repositories {
        miss.get_or_insert(RefreshIneligible::PriorRepositoryProjection);
    }
    if retained {
        miss.get_or_insert(RefreshIneligible::RetainedEvidence);
    }
    let scan: Option<ScanRow> = conn
        .query_row(
            "SELECT len_bytes,fingerprint,provider_id,parser_version FROM source_scans WHERE source_path=?1",
            [&path],
            |r| Ok(ScanRow {
                length: r.get(0)?,
                digest: r.get(1)?,
                provider: r.get(2)?,
                parser: r.get(3)?,
            }),
        )
        .optional()
        .map_err(sql)?;
    let ScanRow {
        length,
        digest: scan_digest,
        provider: scan_provider,
        parser: scan_parser,
    } = scan.ok_or_else(corrupt)?;
    if length < 0
        || scan_parser.is_some_and(|v| v < 0 || v > i64::from(u32::MAX))
        || scan_digest
            .as_ref()
            .is_some_and(|v| !hash_shape(v.strip_prefix("sqlite:").unwrap_or(v)))
        || scan_provider.as_ref().is_some_and(|v| {
            agent_session_grep_ports::SearchProvider::parse(v).is_none_or(|p| p.as_str() != v)
        })
    {
        return Err(corrupt());
    }
    if expected.digest != observation.revision_digest || length as u64 != snapshot.len {
        miss.get_or_insert(RefreshIneligible::DigestOrLength);
    }
    if parser != i64::from(observation.parser_version)
        || scan_parser != Some(i64::from(observation.parser_version))
        || observation.parser_version != crate::PARSER_SEMANTIC_VERSION
    {
        miss.get_or_insert(RefreshIneligible::ParserVersion);
    }
    if scan_digest.as_deref() != Some(expected.digest.as_str())
        || scan_provider.as_deref() != Some(provider.as_str())
    {
        miss.get_or_insert(RefreshIneligible::Scan);
    }
    let content_revision = visible.ok_or_else(corrupt)?;
    let content_ref = managed_receipt::read_checked(conn, &content_revision, Some(source))?;
    let content_retained = validate_original(conn, &content_ref, &incarnation, generation)?;
    let (produces, visible_digest): (Option<String>, Option<String>) = conn
        .query_row(
            "SELECT content_revision_id,content_set_digest FROM source_revision_receipts WHERE revision_id=?1",
            [&content_revision],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .map_err(sql)?;
    let digest = digest.ok_or_else(corrupt)?;
    if !hash_shape(&digest)
        || produces.as_deref() != Some(content_revision.as_str())
        || visible_digest.as_deref() != Some(digest.as_str())
        || (expected.published
            && (content_digest.as_deref() != Some(digest.as_str())
                || (content.as_deref() != Some(content_revision.as_str()) && !content_retained)))
        || stored_content_digest(conn, source, deadline)? != digest
    {
        return Err(corrupt());
    }
    time(deadline)?;
    let sequence: i64 = conn
        .query_row(
            "SELECT MAX(revision_seq) FROM source_revision_receipts WHERE source_id=?1",
            [source],
            |r| r.get(0),
        )
        .map_err(sql)?;
    Ok((
        Baseline {
            content_revision,
            content_digest: digest,
            sequence: sequence.checked_add(1).ok_or_else(corrupt)?,
            generation,
            epoch,
        },
        miss,
    ))
}

fn validate_original(
    conn: &Connection,
    receipt: &RevisionRef,
    incarnation: &str,
    generation: i64,
) -> PortResult<bool> {
    if !receipt.published || receipt.committed_generation.is_none_or(|v| v > generation) {
        return Err(corrupt());
    }
    let mut retained = false;
    if receipt.catalog_incarnation != incarnation {
        if !managed::retained_receipt_matches(conn, receipt, incarnation, generation)? {
            return Err(corrupt());
        }
        retained = true;
    }
    let content: String = conn
        .query_row(
            "SELECT content_revision_id FROM source_revision_receipts WHERE revision_id=?1",
            [receipt.revision_id.as_str()],
            |r| r.get(0),
        )
        .map_err(sql)?;
    if content != receipt.revision_id.as_str() {
        let original = managed_receipt::read_checked(conn, &content, None)?;
        if original.catalog_incarnation != incarnation {
            if !managed::retained_receipt_matches(conn, &original, incarnation, generation)? {
                return Err(corrupt());
            }
            retained = true;
        }
    }
    Ok(retained)
}

fn validate_lineage(
    conn: &Connection,
    binding: &SourceBinding,
    incarnation: &str,
    generation: i64,
    deadline: Instant,
) -> PortResult<(bool, bool)> {
    // The same distinct original-pointer set as full publication. Finish every
    // row even after proven retained evidence so it cannot hide corruption.
    let mut statement = conn
        .prepare(
            "SELECT revision_id FROM source_projections WHERE source_id=?1
             UNION SELECT revision_id FROM source_occurrences WHERE source_id=?1
             UNION SELECT revision_id FROM source_entity_projections WHERE source_id=?1
             UNION SELECT revision_id FROM source_session_projections WHERE source_id=?1
             UNION SELECT visible_revision_id FROM source_heads WHERE source_id=?1 AND visible_revision_id IS NOT NULL",
        )
        .map_err(sql)?;
    let source = binding.source_id.as_str();
    let mut rows = statement.query([source]).map_err(sql)?;
    let mut retained = false;
    let mut empty = true;
    while let Some(row) = rows.next().map_err(sql)? {
        time(deadline)?;
        let id: String = row.get(0).map_err(sql)?;
        let receipt = managed_receipt::read_checked(conn, &id, Some(source))?;
        retained |= validate_original(conn, &receipt, incarnation, generation)?;
        empty &= managed_source_context::verify_refresh_context(conn, binding, &id, deadline)?;
    }
    Ok((retained, empty))
}

fn stored_content_digest(conn: &Connection, source: &str, deadline: Instant) -> PortResult<String> {
    let fingerprints = managed::stored_fingerprints(conn, source)?;
    let mut statement = conn
        .prepare(
            "SELECT payload,payload_digest FROM source_projections WHERE source_id=?1
         UNION ALL SELECT payload,payload_digest FROM source_occurrences WHERE source_id=?1
         UNION ALL SELECT payload,payload_digest FROM source_entity_projections WHERE source_id=?1",
        )
        .map_err(sql)?;
    let mut rows = statement.query([source]).map_err(sql)?;
    while let Some(row) = rows.next().map_err(sql)? {
        time(deadline)?;
        let payload: Vec<u8> = row.get(0).map_err(sql)?;
        let digest: String = row.get(1).map_err(sql)?;
        if !hash_shape(&digest) || managed::digest(&[&payload]) != digest {
            return Err(corrupt());
        }
    }
    let mut statement = conn
        .prepare(
            "SELECT search_text,search_digest FROM source_session_projections WHERE source_id=?1",
        )
        .map_err(sql)?;
    let mut rows = statement.query([source]).map_err(sql)?;
    while let Some(row) = rows.next().map_err(sql)? {
        time(deadline)?;
        let text: String = row.get(0).map_err(sql)?;
        let digest: String = row.get(1).map_err(sql)?;
        if managed::digest(&[text.as_bytes()]) != digest {
            return Err(corrupt());
        }
    }
    let bytes = serde_json::to_vec(&fingerprints).map_err(|_| corrupt())?;
    time(deadline)?;
    Ok(managed::digest(&[&bytes]))
}

fn plain_documents(
    conn: &Connection,
    source: &str,
    provider: &str,
    deadline: Instant,
) -> PortResult<bool> {
    let variant = match provider {
        "claude-code" => "claude-code/jsonl-v1",
        "codex" => "codex/rollout-jsonl-v1",
        _ => return Ok(false),
    };
    let mut statement = conn
        .prepare(
            "SELECT payload FROM source_entity_projections WHERE source_id=?1 AND kind='document'",
        )
        .map_err(sql)?;
    let mut rows = statement.query([source]).map_err(sql)?;
    let mut found = false;
    let mut plain = true;
    while let Some(row) = rows.next().map_err(sql)? {
        time(deadline)?;
        let bytes: Vec<u8> = row.get(0).map_err(sql)?;
        let entity: agent_session_grep_ports::managed::EntityData =
            serde_json::from_slice(&bytes).map_err(|_| corrupt())?;
        let agent_session_grep_ports::managed::EntityData::Document(document) = entity else {
            return Err(corrupt());
        };
        found = true;
        plain &= document.provider_id == provider && document.variant_id == variant;
    }
    Ok(found && plain)
}

pub(crate) fn publish_refresh_in_tx(
    conn: &Connection,
    prior: &RevisionRef,
    observation: &SourceObservation,
    snapshot: &SourceSnapshot,
    policy: &ReadPolicy,
    installation_miss: Option<RefreshIneligible>,
    deadline: Instant,
) -> PortResult<RefreshOutcome> {
    let (base, miss) = baseline(conn, prior, observation, snapshot, policy, deadline)?;
    if let Some(miss) = miss.or(installation_miss) {
        return Ok(RefreshOutcome::Ineligible(miss));
    }
    time(deadline)?;
    let source = observation.binding.source_id.as_str();
    conn.execute(
        "INSERT INTO source_revision_receipts VALUES(?1,?2,?3,?4,?5,'complete',1,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,NULL)",
        params![
            observation.revision_id.as_str(), source, base.sequence,
            observation.revision_digest, observation.parser_version,
            observation.cycle_seq, observation.worker_boot_id,
            observation.catalog_incarnation, observation.policy_epoch,
            observation.started_control_seq, base.content_revision,
            base.content_digest, base.generation, observation.observed_at_ms,
            observation.committed_at_ms
        ],
    ).map_err(sql)?;
    for selection in &observation.selections {
        time(deadline)?;
        conn.execute(
            "INSERT INTO receipt_selection_claims VALUES(?1,?2,?3,?4)",
            params![
                observation.revision_id.as_str(),
                selection.selection_id,
                selection.selection_revision,
                selection.root_identity
            ],
        )
        .map_err(sql)?;
    }
    let count = conn.execute(
        "UPDATE source_heads SET latest_receipt_id=?3,last_attempt_id=?3,observed_cycle_seq=?4
         WHERE source_id=?1 AND latest_receipt_id=?2 AND last_attempt_id=?2 AND update_state='current'
           AND visible_revision_id=?5 AND content_set_digest=?6",
        params![source, prior.revision_id.as_str(), observation.revision_id.as_str(),
            observation.cycle_seq, base.content_revision, base.content_digest],
    ).map_err(sql)?;
    if count != 1 {
        return Err(changed());
    }
    conn.execute(
        "DELETE FROM source_scope_claims WHERE source_id=?1",
        [source],
    )
    .map_err(sql)?;
    for selection in &observation.selections {
        time(deadline)?;
        conn.execute(
            "INSERT INTO source_scope_claims VALUES(?1,?2,?3,?4,?5)",
            params![
                source,
                selection.selection_id,
                selection.selection_revision,
                observation.policy_epoch,
                observation.observed_at_ms
            ],
        )
        .map_err(sql)?;
    }
    managed_source_context::persist_empty_refresh_context(conn, observation, policy, deadline)?;
    let scans = conn.execute(
        "UPDATE source_scans SET scanned_at_ms=?2,len_bytes=?3,fingerprint=?4,provider_id=?5,parser_version=?6 WHERE source_path=?1",
        params![observation.binding.source_path, observation.observed_at_ms, snapshot.len as i64,
            observation.revision_digest, observation.binding.provider.as_str(), observation.parser_version],
    ).map_err(sql)?;
    if scans != 1 {
        return Err(corrupt());
    }
    let receipt =
        managed_receipt::read_checked(conn, observation.revision_id.as_str(), Some(source))?;
    let expected = RevisionRef {
        revision_id: observation.revision_id.clone(),
        digest: observation.revision_digest.clone(),
        observed_at_ms: observation.observed_at_ms,
        cycle_seq: observation.cycle_seq,
        worker_boot_id: observation.worker_boot_id.clone(),
        catalog_incarnation: observation.catalog_incarnation.clone(),
        policy_epoch: observation.policy_epoch,
        started_control_seq: observation.started_control_seq,
        committed_generation: Some(base.generation),
        published: true,
    };
    if receipt != expected
        || !managed_source_context::receipt_context_current(
            conn,
            observation.revision_id.as_str(),
            Some(policy),
            deadline,
        )?
    {
        return Err(corrupt());
    }
    if !managed_source_context::verify_refresh_context_head(
        conn,
        &observation.binding,
        observation.revision_id.as_str(),
        deadline,
    )? {
        return Err(corrupt());
    }
    time(deadline)?;
    Ok(RefreshOutcome::Refreshed(Publication {
        receipt,
        content_changed: false,
        destructive: false,
        required_generation: base.generation,
        destructive_epoch: base.epoch,
    }))
}
