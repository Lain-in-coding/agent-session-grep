//! Completed discovery receipts and independently owned original observations.
use agent_session_grep_ports::{
    PortError, PortResult, control,
    managed::{DiscoveryObservation, DiscoverySource, RevisionRef, SelectionProof, SourceId},
};
use rusqlite::{Connection, OptionalExtension, params};
use std::{
    cell::{Cell, RefCell},
    collections::BTreeMap,
    time::Instant,
};

type StoredDiscovery = (i64, String, i64, i64, String, String, String, bool);

/// The facade supplies control reads while holding its HistoryReaders guard.
/// Catalog code never opens control or provider files to reconstruct ownership.
pub(crate) trait OriginalCycleValidator {
    fn cycle(&self, seq: control::CycleSeq, end: Instant) -> PortResult<control::ObservationCycle>;
}

pub(crate) struct OriginalCycleProof<'a> {
    validator: &'a dyn OriginalCycleValidator,
    cycles: RefCell<BTreeMap<i64, Option<control::ObservationCycle>>>,
    selection_count: Cell<usize>,
    end: Instant,
}
impl<'a> OriginalCycleProof<'a> {
    pub(crate) fn new(validator: &'a dyn OriginalCycleValidator, end: Instant) -> Self {
        Self {
            validator,
            cycles: RefCell::new(BTreeMap::new()),
            selection_count: Cell::new(0),
            end,
        }
    }

    pub(crate) fn validates(
        &self,
        seq: i64,
        boot: &str,
        policy: i64,
        started: i64,
        selection: &SelectionProof,
    ) -> PortResult<bool> {
        time(self.end)?;
        let number = control::CycleSeq::new(seq)?;
        if !self.cycles.borrow().contains_key(&seq) {
            if self.cycles.borrow().len() >= 16_384 {
                return Err(PortError::WriterBusy(
                    "discovery ownership exceeds bounded capacity".into(),
                ));
            }
            let cycle = match self.validator.cycle(number, self.end) {
                Ok(cycle) => Some(cycle),
                Err(PortError::NotFound(_)) => None,
                Err(error) => return Err(error),
            };
            time(self.end)?;
            let selections = cycle.as_ref().map_or(0, |c| c.selections.len());
            let total = self.selection_count.get().saturating_add(selections);
            if selections > 4096
                || total > agent_session_grep_ports::source_context::MAX_AUTHORITY_KEYS
            {
                return Err(PortError::WriterBusy(
                    "discovery ownership claims exceed bounded capacity".into(),
                ));
            }
            self.selection_count.set(total);
            self.cycles.borrow_mut().insert(seq, cycle);
        }
        let cycles = self.cycles.borrow();
        let Some(cycle) = cycles.get(&seq).and_then(Option::as_ref) else {
            return Ok(false);
        };
        Ok(cycle.token.cycle_seq == number
            && cycle.token.worker_boot_id.as_str() == boot
            && cycle.policy_epoch.get() == policy
            && cycle.state != control::CycleState::Queued
            && started > cycle.admitted_control_seq.get()
            && cycle.started_control_seq.map(|s| s.get()) == Some(started)
            && cycle
                .selections
                .iter()
                .filter(|s| {
                    s.selection.selection_id.as_str() == selection.selection_id
                        && s.selection.revision.get() == selection.selection_revision
                        && s.selection.root_identity.as_str() == selection.root_identity
                })
                .count()
                == 1)
    }

    pub(crate) fn receipt(
        &self,
        receipt: &RevisionRef,
        selection: &SelectionProof,
    ) -> PortResult<bool> {
        self.validates(
            receipt.cycle_seq,
            &receipt.worker_boot_id,
            receipt.policy_epoch,
            receipt.started_control_seq,
            selection,
        )
    }
}

#[derive(Clone, Copy)]
enum DiscoveryProofMode {
    ExactCycle,
    PlainEpoch,
}

fn invalid() -> PortError {
    PortError::InvalidRequest("invalid discovery receipt".into())
}
/// Busy, locked and deadline-interrupted statements are retryable within the
/// caller's remaining budget; only other storage failures are corruption.
fn sql(error: rusqlite::Error) -> PortError {
    match error.sqlite_error_code() {
        Some(
            rusqlite::ErrorCode::DatabaseBusy
            | rusqlite::ErrorCode::DatabaseLocked
            | rusqlite::ErrorCode::OperationInterrupted,
        ) => PortError::WriterBusy("discovery receipt storage is busy or past its deadline".into()),
        _ => PortError::SchemaIncompatible("discovery receipt storage is unavailable".into()),
    }
}
fn corrupt() -> PortError {
    PortError::SchemaIncompatible("discovery receipt proof is invalid".into())
}
fn time(end: Instant) -> PortResult<()> {
    if Instant::now() >= end {
        Err(PortError::WriterBusy(
            "discovery receipt deadline reached".into(),
        ))
    } else {
        Ok(())
    }
}

fn plain_binding(provider: &str, path: &str, digest: &str) -> bool {
    matches!(provider, "claude-code" | "codex")
        && path.ends_with(".jsonl")
        && (digest == "confirmed_absent"
            || (digest.len() == 64
                && digest
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))))
}

/// Historical eligibility deliberately ignores today's parser/scan/head.
pub(crate) fn plain_receipt(conn: &Connection, receipt: &RevisionRef) -> PortResult<bool> {
    let (provider, path): (String, String) = conn
        .query_row(
            "SELECT b.provider_id,b.source_path FROM source_revision_receipts r
         JOIN source_bindings b USING(source_id) WHERE r.revision_id=?1",
            [receipt.revision_id.as_str()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .map_err(sql)?;
    if !plain_binding(&provider, &path, &receipt.digest) {
        return Ok(false);
    }
    let has_context: bool = conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name='source_publication_contexts')",
            [],
            |r| r.get(0),
        )
        .map_err(sql)?;
    if !has_context {
        return Ok(false);
    }
    let context: Option<(i64, Option<String>)> = conn.query_row(
        "SELECT dependency_count,authority_id FROM source_publication_contexts WHERE revision_id=?1",
        [receipt.revision_id.as_str()], |r| Ok((r.get(0)?, r.get(1)?)),
    ).optional().map_err(sql)?;
    if context != Some((0, None)) {
        return Ok(false);
    }
    let source: String = conn
        .query_row(
            "SELECT source_id FROM source_revision_receipts WHERE revision_id=?1",
            [receipt.revision_id.as_str()],
            |r| r.get(0),
        )
        .map_err(sql)?;
    crate::managed_source_context::verify_context_for_retirement(
        conn,
        receipt.revision_id.as_str(),
        &source,
    )?;
    let expected = crate::managed_source_context::context_manifest(
        &agent_session_grep_ports::source_context::SourcePublicationContext::default(),
    )?;
    let manifest: Vec<u8> = conn
        .query_row(
            "SELECT manifest FROM source_publication_contexts WHERE revision_id=?1",
            [receipt.revision_id.as_str()],
            |r| r.get(0),
        )
        .map_err(sql)?;
    Ok(manifest == expected)
}

pub(crate) fn receipt_claim(
    conn: &Connection,
    receipt: &RevisionRef,
    selection: &SelectionProof,
) -> PortResult<bool> {
    let claim: Option<(i64, String)> = conn
        .query_row(
            "SELECT selection_revision,root_identity FROM receipt_selection_claims
         WHERE revision_id=?1 AND selection_id=?2",
            params![receipt.revision_id.as_str(), selection.selection_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()
        .map_err(sql)?;
    let Some((revision, root)) = claim else {
        return Ok(false);
    };
    control::ControlId::parse(&root).map_err(|_| corrupt())?;
    if revision < 1 {
        return Err(corrupt());
    }
    Ok(revision == selection.selection_revision && root == selection.root_identity)
}

pub(crate) fn current_plain_baseline(
    conn: &Connection,
    source: &SourceId,
    policy: &control::ReadPolicy,
    end: Instant,
) -> PortResult<Option<RevisionRef>> {
    time(end)?;
    let latest: Option<String> = conn
        .query_row(
            "SELECT latest_receipt_id FROM source_heads WHERE source_id=?1",
            [source.as_str()],
            |r| r.get(0),
        )
        .optional()
        .map_err(sql)?
        .flatten();
    let Some(latest) = latest else {
        return Ok(None);
    };
    let receipt = crate::managed_receipt::read_checked(conn, &latest, Some(source.as_str()))?;
    if !plain_receipt(conn, &receipt)?
        || !crate::managed_source_context::receipt_context_current(
            conn,
            &latest,
            Some(policy),
            end,
        )?
    {
        return Ok(None);
    }
    let (provider, path): (String, String) = conn
        .query_row(
            "SELECT provider_id,source_path FROM source_bindings WHERE source_id=?1",
            [source.as_str()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .map_err(sql)?;
    let provider = agent_session_grep_ports::SearchProvider::parse(&provider)
        .filter(|p| p.as_str() == provider)
        .ok_or_else(corrupt)?;
    let locator = control::CanonicalLocator::parse(&path).map_err(|_| corrupt())?;
    let mut scope_current = false;
    for selection in policy
        .selections
        .iter()
        .filter(|s| s.enabled && s.region.matches(provider, &locator))
    {
        time(end)?;
        let Some(root) = selection.root_identity.as_ref() else {
            continue;
        };
        scope_current = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM source_scope_claims s
             JOIN receipt_selection_claims c ON c.selection_id=s.selection_id
             WHERE s.source_id=?1 AND c.revision_id=?2 AND s.selection_id=?3
             AND s.selection_revision=?4 AND c.selection_revision=?4
             AND s.policy_epoch=?5 AND c.root_identity=?6)",
                params![
                    source.as_str(),
                    latest,
                    selection.id.as_str(),
                    selection.revision.get(),
                    policy.policy_epoch.get(),
                    root.as_str()
                ],
                |r| r.get(0),
            )
            .map_err(sql)?;
        if scope_current {
            break;
        }
    }
    if !scope_current {
        return Ok(None);
    }
    let valid: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM source_heads h
         JOIN source_revision_receipts r ON r.revision_id=h.latest_receipt_id AND r.source_id=h.source_id
         JOIN source_bindings b ON b.source_id=h.source_id
         JOIN source_scans s ON s.source_path=b.source_path
         WHERE h.source_id=?1 AND h.latest_receipt_id=h.last_attempt_id AND h.update_state='current'
         AND h.visible_revision_id=r.content_revision_id AND h.content_set_digest=r.content_set_digest
         AND h.observed_cycle_seq=r.cycle_seq AND r.published=1
         AND r.parser_version=?2 AND r.parser_version=s.parser_version AND s.provider_id=b.provider_id
         AND s.fingerprint=r.revision_digest AND s.len_bytes>=0
         AND (b.namespace_id IS NULL OR EXISTS(
             SELECT 1 FROM source_installations i JOIN installation_namespaces n USING(namespace_id)
             WHERE i.source_path=b.source_path AND i.namespace_id=b.namespace_id AND n.provider_id=b.provider_id))
         AND r.committed_generation<=(SELECT active_generation FROM store_metadata WHERE singleton=1))",
        params![source.as_str(), crate::PARSER_SEMANTIC_VERSION], |r| r.get(0),
    ).map_err(sql)?;
    time(end)?;
    Ok(valid.then_some(receipt))
}

pub(crate) fn validate_receipt_ownership(
    conn: &Connection,
    receipt: &RevisionRef,
    ownership: &OriginalCycleProof<'_>,
    end: Instant,
) -> PortResult<bool> {
    let mut statement = conn
        .prepare(
            "SELECT selection_id,selection_revision,root_identity FROM receipt_selection_claims
         WHERE revision_id=?1 ORDER BY selection_id",
        )
        .map_err(sql)?;
    let mut rows = statement
        .query([receipt.revision_id.as_str()])
        .map_err(sql)?;
    let mut count = 0;
    while let Some(row) = rows.next().map_err(sql)? {
        time(end)?;
        count += 1;
        if count > 4096 {
            return Err(PortError::WriterBusy(
                "discovery claims exceed bounded capacity".into(),
            ));
        }
        let selection = SelectionProof {
            selection_id: row.get(0).map_err(sql)?,
            selection_revision: row.get(1).map_err(sql)?,
            root_identity: row.get(2).map_err(sql)?,
        };
        control::ControlId::parse(&selection.selection_id)?;
        control::ControlId::parse(&selection.root_identity)?;
        if selection.selection_revision < 1 || !ownership.receipt(receipt, &selection)? {
            return Ok(false);
        }
    }
    Ok(count > 0)
}

/// One historical member relation, reused by reads and typed retention.
pub(crate) fn member_cycle_matches(
    conn: &Connection,
    receipt: &RevisionRef,
    closing_cycle: i64,
    closing_start: i64,
) -> PortResult<bool> {
    if plain_receipt(conn, receipt)? {
        Ok(receipt.cycle_seq > 0
            && receipt.cycle_seq <= closing_cycle
            && receipt.started_control_seq > 0
            && receipt.started_control_seq <= closing_start
            && (receipt.cycle_seq != closing_cycle || receipt.started_control_seq == closing_start))
    } else {
        Ok(receipt.cycle_seq == closing_cycle && receipt.started_control_seq == closing_start)
    }
}

pub(crate) fn source_set_digest(sources: &[DiscoverySource]) -> PortResult<String> {
    let mut sorted: Vec<_> = sources.iter().collect();
    sorted.sort_by(|a, b| a.source_id.cmp(&b.source_id));
    if sorted.windows(2).any(|s| s[0].source_id == s[1].source_id) {
        return Err(invalid());
    }
    let mut hash = blake3::Hasher::new();
    hash.update(b"asg-discovery-source-set-v1");
    for source in sorted {
        for field in [source.source_id.as_str(), source.revision_id.as_str()] {
            hash.update(&(field.len() as u64).to_le_bytes());
            hash.update(field.as_bytes());
        }
    }
    Ok(hash.finalize().to_hex().to_string())
}

#[cfg(test)]
pub(crate) fn publish_in_tx(
    conn: &Connection,
    observation: &DiscoveryObservation,
) -> PortResult<()> {
    publish_with_deadline_in_tx(
        conn,
        observation,
        None,
        std::time::Instant::now() + std::time::Duration::from_secs(10),
    )
}
pub(crate) fn publish_with_deadline_in_tx(
    conn: &Connection,
    observation: &DiscoveryObservation,
    policy: Option<&agent_session_grep_ports::control::ReadPolicy>,
    deadline: std::time::Instant,
) -> PortResult<()> {
    publish(
        conn,
        observation,
        policy,
        deadline,
        DiscoveryProofMode::ExactCycle,
        None,
    )
}

pub(crate) fn publish_epoch_with_deadline_in_tx(
    conn: &Connection,
    observation: &DiscoveryObservation,
    policy: &control::ReadPolicy,
    end: Instant,
    validator: &dyn OriginalCycleValidator,
) -> PortResult<()> {
    let proof = OriginalCycleProof::new(validator, end);
    publish(
        conn,
        observation,
        Some(policy),
        end,
        DiscoveryProofMode::PlainEpoch,
        Some(&proof),
    )
}

fn publish(
    conn: &Connection,
    observation: &DiscoveryObservation,
    policy: Option<&control::ReadPolicy>,
    deadline: Instant,
    mode: DiscoveryProofMode,
    ownership: Option<&OriginalCycleProof<'_>>,
) -> PortResult<()> {
    let check = || time(deadline);
    check()?;
    if conn.is_autocommit()
        || (!observation.complete && !observation.sources.is_empty())
        || observation.cycle_seq < 1
        || observation.policy_epoch < 0
        || observation.started_control_seq < 1
        || observation.selection.selection_revision < 1
    {
        return Err(invalid());
    }
    if matches!(mode, DiscoveryProofMode::PlainEpoch) {
        let owned = ownership.ok_or_else(invalid)?;
        if !observation.complete
            || !owned.validates(
                observation.cycle_seq,
                &observation.worker_boot_id,
                observation.policy_epoch,
                observation.started_control_seq,
                &observation.selection,
            )?
        {
            return Err(invalid());
        }
        let newest: Option<i64> = conn
            .query_row(
                "SELECT MAX(cycle_seq) FROM discovery_receipts WHERE selection_id=?1",
                [&observation.selection.selection_id],
                |r| r.get(0),
            )
            .map_err(sql)?;
        if newest != Some(observation.cycle_seq) {
            return Err(invalid());
        }
    }
    let generation: i64 = conn
        .query_row(
            "SELECT active_generation FROM store_metadata WHERE singleton=1",
            [],
            |r| r.get(0),
        )
        .map_err(sql)?;
    let digest = source_set_digest(&observation.sources)?;
    for source in &observation.sources {
        check()?;
        let receipt = crate::managed_receipt::read_checked(
            conn,
            source.revision_id.as_str(),
            Some(source.source_id.as_str()),
        )?;
        if !crate::managed_source_context::receipt_context_current(
            conn,
            source.revision_id.as_str(),
            policy,
            deadline,
        )? {
            return Err(invalid());
        }
        let plain =
            matches!(mode, DiscoveryProofMode::PlainEpoch) && plain_receipt(conn, &receipt)?;
        let cycle_matches = if plain {
            member_cycle_matches(
                conn,
                &receipt,
                observation.cycle_seq,
                observation.started_control_seq,
            )? && ownership
                .ok_or_else(invalid)?
                .receipt(&receipt, &observation.selection)?
                && current_plain_baseline(
                    conn,
                    &source.source_id,
                    policy.ok_or_else(invalid)?,
                    deadline,
                )?
                .as_ref()
                    == Some(&receipt)
        } else {
            receipt.cycle_seq == observation.cycle_seq
                && receipt.started_control_seq == observation.started_control_seq
        };
        if !receipt.published
            || !cycle_matches
            || receipt.worker_boot_id != observation.worker_boot_id
            || receipt.policy_epoch != observation.policy_epoch
            || receipt.catalog_incarnation != observation.catalog_incarnation
            || receipt
                .committed_generation
                .is_none_or(|value| value > generation)
        {
            return Err(invalid());
        }
        let valid:bool=conn.query_row("SELECT EXISTS(SELECT 1 FROM source_revision_receipts r JOIN source_heads h USING(source_id) JOIN receipt_selection_claims c USING(revision_id) JOIN source_scope_claims sc ON sc.source_id=r.source_id AND sc.selection_id=c.selection_id WHERE r.source_id=?1 AND r.revision_id=?2 AND r.published=1 AND r.cycle_seq=?3 AND r.worker_boot_id=?4 AND r.policy_epoch=?5 AND r.started_control_seq=?6 AND r.catalog_incarnation=?7 AND c.selection_id=?8 AND c.selection_revision=?9 AND c.root_identity=?10 AND h.latest_receipt_id=r.revision_id AND h.last_attempt_id=r.revision_id AND r.committed_generation<=?11 AND sc.selection_revision=c.selection_revision AND sc.policy_epoch=r.policy_epoch)",params![source.source_id.as_str(),source.revision_id.as_str(),receipt.cycle_seq,observation.worker_boot_id,observation.policy_epoch,receipt.started_control_seq,observation.catalog_incarnation,observation.selection.selection_id,observation.selection.selection_revision,observation.selection.root_identity,generation],|r|r.get(0)).map_err(sql)?;
        if !valid {
            return Err(invalid());
        }
    }
    if matches!(mode, DiscoveryProofMode::PlainEpoch) {
        let policy = policy.ok_or_else(invalid)?;
        let selection = policy
            .selections
            .iter()
            .find(|s| {
                s.enabled
                    && s.id.as_str() == observation.selection.selection_id
                    && s.revision.get() == observation.selection.selection_revision
                    && s.root_identity.as_ref().map(control::ControlId::as_str)
                        == Some(observation.selection.root_identity.as_str())
            })
            .ok_or_else(invalid)?;
        let represented: std::collections::BTreeSet<_> = observation
            .sources
            .iter()
            .map(|s| s.source_id.as_str())
            .collect();
        let mut statement = conn
            .prepare(
                "SELECT source_id,provider_id,source_path FROM source_bindings ORDER BY source_id",
            )
            .map_err(sql)?;
        let mut rows = statement.query([]).map_err(sql)?;
        while let Some(row) = rows.next().map_err(sql)? {
            check()?;
            let source: String = row.get(0).map_err(sql)?;
            let provider: String = row.get(1).map_err(sql)?;
            let provider =
                agent_session_grep_ports::SearchProvider::parse(&provider).ok_or_else(invalid)?;
            let locator = control::CanonicalLocator::parse(&row.get::<_, String>(2).map_err(sql)?)?;
            if matches!(provider.as_str(), "claude-code" | "codex")
                && selection.region.matches(provider, &locator)
                && policy.allows_source(provider, &locator, &control::ControlId::parse(&source)?)
                && !represented.contains(source.as_str())
            {
                return Err(invalid());
            }
        }
    }
    check()?;
    let existing:Option<StoredDiscovery>=conn.query_row("SELECT selection_revision,worker_boot_id,policy_epoch,started_control_seq,catalog_incarnation,root_identity,source_set_digest,complete FROM discovery_receipts WHERE cycle_seq=?1 AND selection_id=?2",params![observation.cycle_seq,observation.selection.selection_id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?,r.get(7)?))).optional().map_err(sql)?;
    if let Some(prior) = existing {
        let identity = (
            observation.selection.selection_revision,
            observation.worker_boot_id.clone(),
            observation.policy_epoch,
            observation.started_control_seq,
            observation.catalog_incarnation.clone(),
            observation.selection.root_identity.clone(),
            prior.6.clone(),
            prior.7,
        );
        if prior != identity {
            return Err(invalid());
        }
        // Only an incomplete attempt may become complete. Its provisional set
        // must be empty; a completed receipt is immutable, even on retry.
        if !prior.7 && observation.complete {
            let empty = source_set_digest(&[])?;
            let count: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM discovery_sources WHERE cycle_seq=?1 AND selection_id=?2",
                    params![observation.cycle_seq, observation.selection.selection_id],
                    |r| r.get(0),
                )
                .map_err(sql)?;
            if prior.6 != empty || count != 0 {
                return Err(invalid());
            }
            conn.execute("UPDATE discovery_receipts SET source_set_digest=?3,complete=1,committed_generation=?4 WHERE cycle_seq=?1 AND selection_id=?2 AND complete=0",
                params![observation.cycle_seq,observation.selection.selection_id,digest,generation]).map_err(sql)?;
            insert_sources(conn, observation)?;
            return check();
        }
        if prior.7 != observation.complete || prior.6 != digest {
            return Err(invalid());
        }
        let mut stmt=conn.prepare("SELECT source_id,revision_id FROM discovery_sources WHERE cycle_seq=?1 AND selection_id=?2 ORDER BY source_id").map_err(sql)?;
        let stored = stmt
            .query_map(
                params![observation.cycle_seq, observation.selection.selection_id],
                |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
            )
            .map_err(sql)?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(sql)?;
        let mut expected: Vec<_> = observation
            .sources
            .iter()
            .map(|s| {
                (
                    s.source_id.as_str().to_string(),
                    s.revision_id.as_str().to_string(),
                )
            })
            .collect();
        expected.sort();
        return if stored == expected {
            check()
        } else {
            Err(invalid())
        };
    }
    conn.execute(
        "INSERT INTO discovery_receipts VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
        params![
            observation.cycle_seq,
            observation.selection.selection_id,
            observation.selection.selection_revision,
            observation.worker_boot_id,
            observation.policy_epoch,
            observation.started_control_seq,
            observation.catalog_incarnation,
            observation.selection.root_identity,
            digest,
            observation.complete,
            generation
        ],
    )
    .map_err(sql)?;
    insert_sources(conn, observation)?;
    check()
}

fn insert_sources(conn: &Connection, observation: &DiscoveryObservation) -> PortResult<()> {
    for source in &observation.sources {
        conn.execute(
            "INSERT INTO discovery_sources VALUES(?1,?2,?3,?4)",
            params![
                observation.cycle_seq,
                observation.selection.selection_id,
                source.source_id.as_str(),
                source.revision_id.as_str()
            ],
        )
        .map_err(sql)?;
    }
    Ok(())
}
